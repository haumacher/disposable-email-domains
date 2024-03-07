package com.github.spamchecker.db;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

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

import com.github.spamchecker.db.model.Domain;

public class DbLoader {

	public static void main(String[] args) throws IOException, SQLException {
		new DbLoader().run();
	}

	private SqlSessionFactory _sessionFactory;
	private JdbcConnectionPool _pool;

	private void run() throws IOException, SQLException {
		initDb();
		
		try (SqlSession session = _sessionFactory.openSession()) {
			DB db = session.getMapper(DB.class);
			
			Domain domain;
			db.insertDomain(domain = Domain.create().setName("foo.bar").setHeuristics("xxx").setClassification("zzz"));
			
			System.out.println(domain.getId());
		}
		
		shutdownDb();
	}

	private void initDb() {
		boolean dbExists = new File("./fakedomain.mv.db").exists();
		
		setupDb();
		
		if (!dbExists) {
			try (SqlSession session = _sessionFactory.openSession()) {
				ScriptRunner sr = new ScriptRunner(session.getConnection());
				sr.setAutoCommit(true);
				sr.setDelimiter(";");
				sr.runScript(new InputStreamReader(DbLoader.class.getResourceAsStream("db-schema.sql"), StandardCharsets.UTF_8));
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
