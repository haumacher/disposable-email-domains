package com.github.spamchecker;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.apache.ibatis.jdbc.ScriptRunner;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.TransactionFactory;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.h2.jdbcx.JdbcConnectionPool;
import org.h2.jdbcx.JdbcDataSource;
import org.xbill.DNS.Address;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class MxResolver {

	public static void main(String[] args) throws IOException, SQLException {
		new MxResolver().run();
	}

	private SqlSessionFactory _sessionFactory;
	private JdbcConnectionPool _pool;

	private void run() throws IOException, SQLException {
		initDb();
		
		try (SqlSession session = _sessionFactory.openSession()) {
			DB db = session.getMapper(DB.class);
			
			try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File("./disposable_email_blocklist.conf")), StandardCharsets.UTF_8))) {
				String line;
				String service = null;
				Long serviceId = null;
				while ((line = r.readLine()) != null) {
					if (line.startsWith("#")) {
						service = line.substring(1).trim();
						if (service.isEmpty()) {
							service = null;
							serviceId = null;
						} else {
							serviceId = enterService(db, service);
						}
						continue;
					}
					
					String domain = line.trim().toLowerCase();
					if (domain.isEmpty()) {
						serviceId = null;
						continue;
					}

					if (db.lookupDisposable(domain) != null) {
						// Already present.
						
						if (serviceId != null) {
							int cnt = db.updateDomain(domain, serviceId);
							if (cnt > 0) {
								System.out.println("Updating domain: " + domain + (service != null ? " (" + service + ")" : ""));
							}
						}
					} else {
						enterDomain(db, domain, serviceId);
					}
					
					session.commit();
				}
			}
		}
	}

	private Record[] enterDomain(DB db, String domain, Long serviceId) throws TextParseException { 
		System.out.println("Processing domain: " + domain + (serviceId != null ? " (" + serviceId + ")" : ""));
		db.insertDomain(domain, serviceId);
		
		Record[] records = new Lookup(domain, Type.MX).run();
		if (records == null) {
			// Domain is its own mail server.
			try {
				enterMx(db, domain, domain);
			} catch (UnknownHostException e) {
				System.err.println("Fallback mail server does not exist for: " + domain);
			}
		} else {
			for (int i = 0; i < records.length; i++) {
				MXRecord mx = (MXRecord) records[i];
				String mailServer = mx.getTarget().toString();
				
				try {
					enterMx(db, domain, mailServer);
				} catch (UnknownHostException e) {
					System.err.println("Mail server does not exist: " + mailServer + " (" + domain + ")");
				}
			}
		}
		return records;
	}

	private Long enterService(DB db, String service) {
		Long serviceId;
		if (service != null) {
			serviceId = db.getServiceId(service);
			if (serviceId == null) {
				Service serviceObj = new Service(0, service);
				db.insertService(serviceObj);
				
				serviceId = serviceObj.id; 
				
				System.out.println("Created Service: " + service + " (" + serviceId + ")");
			}
		} else {
			serviceId = null;
		}
		return serviceId;
	}

	private void enterMx(DB db, String domain, String mailServer) throws UnknownHostException {
		Boolean dead = db.getHostState(mailServer);
		if (dead == null) {
			System.out.println("\tCreating mail server: " + mailServer);
			db.insertMailHost(mailServer);
			
			InetAddress[] addresses = Address.getAllByName(mailServer);
			for (InetAddress address : addresses) {
				String hostAddress = address.getHostAddress();
				
				System.out.println("\t\tAddress: " + hostAddress);
				db.insertMxIp(mailServer, hostAddress);
			}
		} else {
			System.out.println("\tReusing mail server: " + mailServer);
		}
		
		// Found new mail server. 
		db.insertMx(domain, mailServer);
	}

	private void initDb() {
		boolean dbExists = new File("./fakedomain.mv.db").exists();
		
		setupDb();
		
		if (!dbExists) {
			try (SqlSession session = _sessionFactory.openSession()) {
				ScriptRunner sr = new ScriptRunner(session.getConnection());
				sr.setAutoCommit(true);
				sr.setDelimiter(";");
				sr.runScript(new InputStreamReader(MxResolver.class.getResourceAsStream("db-schema.sql"), StandardCharsets.UTF_8));
			}
		}
	}

	private void setupDb() {
		JdbcDataSource dataSource = new JdbcDataSource();
		dataSource.setUrl("jdbc:h2:./fakedomain");
		dataSource.setUser("user");
		dataSource.setPassword("passwd");
		_pool = JdbcConnectionPool.create(dataSource);
		
		TransactionFactory transactionFactory = new JdbcTransactionFactory();
		Environment environment = new Environment("phoneblock", transactionFactory, _pool);
		Configuration configuration = new Configuration(environment);
		configuration.setUseActualParamName(true);
		configuration.addMapper(DB.class);
		_sessionFactory = new SqlSessionFactoryBuilder().build(configuration);
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				try {
					shutdownDb();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		});
	}

	private void shutdownDb() throws SQLException {
		if (_sessionFactory != null) {
//			try (SqlSession session = _sessionFactory.openSession()) {
//				try (Statement statement = session.getConnection().createStatement()) {
//					statement.execute("SHUTDOWN");
//				}
//			}
			_sessionFactory = null;
		}

		if (_pool != null) {
			_pool.dispose();
			_pool = null;
		}
	}
	
}
