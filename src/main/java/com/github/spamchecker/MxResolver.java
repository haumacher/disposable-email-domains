package com.github.spamchecker;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.xbill.DNS.Address;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import com.github.spamchecker.model.Classification;
import com.github.spamchecker.model.DB;
import com.github.spamchecker.model.DomainInfo;
import com.github.spamchecker.model.Heuristics;
import com.github.spamchecker.model.MxInfo;

import de.haumacher.msgbuf.json.JsonReader;
import de.haumacher.msgbuf.json.JsonWriter;
import de.haumacher.msgbuf.server.io.ReaderAdapter;
import de.haumacher.msgbuf.server.io.WriterAdapter;

public class MxResolver {
	
	public static void main(String[] args) throws IOException, SQLException {
		new MxResolver().run(args);
	}
	
	String _outFile = "-";

	private void run(String[] args) throws TextParseException, IOException, SQLException {
		if (args.length == 0) {
			System.err.println("Missing command.");
			System.exit(-1);
		}
		
		for (int n = 0, cnt = args.length; n < cnt; n++) {
			String cmd = args[n];
			
			switch (cmd) {
			case "-out":
				_outFile = args[++n];
				break;
				
			case "query": 
				DomainInfo query = query(args[++n]);
				System.out.println(query);
				break;
			case "classify": 
				classify(args[++n]);
				break;
			case "load-disposable": 
				load(args[++n], Classification.DISPOSABLE);
				break;
			case "load-regular": 
				load(args[++n], Classification.REGULAR);
				break;
			case "load-dead": 
				load(args[++n], Classification.DEAD);
				break;
			case "reset": 
				resetDb();
				break;
			case "use-db":
				_db = loadDb(new File(args[++n]));
				break;
			case "dump-disposables":
				dumpDisposables();
				break;
			default:
				System.err.println("Unknown command: " + cmd);
				System.exit(-1);
			}
		}
	}

	private void dumpDisposables() {
		List<String> result = new ArrayList<>();
		for (Entry<String, DomainInfo> entry : _db.getDomains().entrySet()) {
			if (entry.getValue().getKind() == Classification.DISPOSABLE) {
				result.add(entry.getKey());
			}
		}
		Collections.sort(result);
		for (String domain : result) {
			System.out.println(domain);
		}
	}

	private void classify(String fileName) throws IOException {
		DB newDb = DB.create();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(fileName)), StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.startsWith("#")) {
					continue;
				}
				
				String domain = line.trim().toLowerCase();
				if (domain.isEmpty()) {
					continue;
				}

				DomainInfo info = query(domain);
				System.err.println(domain + ": " + info);
				
				newDb.getDomains().put(domain, info);
			}
		}
		
		// Copy mail server section to result.
		for (DomainInfo domain : newDb.getDomains().values()) {
			for (String mx : domain.getMailServers()) {
				newDb.getMailServers().put(mx, _db.getMailServers().get(mx));
			}
		}
		updateClassifications(newDb);
		
		writeTo(outStream(), newDb);
	}

	private OutputStream outStream() throws FileNotFoundException {
		return "-".equals(_outFile) ? System.out : new FileOutputStream(new File(_outFile));
	}

	private DomainInfo query(String domain) throws TextParseException {
		Map<String, Classification> addressClassification = buildAddressClassification();
		Map<String, Set<String>> serviceByMx = buildServicesByMx();
		Map<String, Set<String>> serviceByAddress = buildServicesByAddress();
		
		DomainInfo existingDomain = getDomain(domain);
		if (existingDomain != null) {
			return existingDomain;
		}
		
		DomainInfo newDomain = enterDomain(domain, null, Classification.UNKNOWN);
		
		Classification mxGuess = Classification.UNKNOWN;
		Classification addressGuess = Classification.UNKNOWN;
		Set<String> mxServices = new HashSet<>();
		Set<String> addressServices = new HashSet<>();
		for (String mx : newDomain.getMailServers()) {
			MxInfo mxInfo = _db.getMailServers().get(mx);
			mxGuess = anyDisposable(mxGuess, mxInfo.getKind());

			for (String address : mxInfo.getAddresses()) {
				addressGuess = anyDisposable(addressGuess, addressClassification.getOrDefault(address, Classification.UNKNOWN));
				
				addressServices.addAll(serviceByAddress.getOrDefault(address, Collections.emptySet()));
			}
			
			mxServices.addAll(serviceByMx.getOrDefault(mx, Collections.emptySet()));
		}
		
		if (mxGuess != Classification.UNKNOWN) {
			newDomain.setKind(mxGuess);
			newDomain.setHeuristics(Heuristics.MX);
			setService(newDomain, mxServices);
			return newDomain;
		}
		
		if (addressGuess != Classification.UNKNOWN) {
			newDomain.setKind(addressGuess);
			newDomain.setHeuristics(Heuristics.IP);
			setService(newDomain, addressServices);
			return newDomain;
		}
		
		if (newDomain.getKind() != Classification.DEAD) {
			newDomain.setHeuristics(Heuristics.NONE);
		}
		return newDomain;
	}

	private void setService(DomainInfo newDomain, Set<String> mxServices) {
		if (mxServices.size() == 1) {
			newDomain.setService(mxServices.iterator().next());
		} else {
			newDomain.setPotentialServices(sorted(mxServices));
		}
	}

	private ArrayList<String> sorted(Set<String> services) {
		ArrayList<String> result = new ArrayList<>(services);
		Collections.sort(result);
		return result;
	}

	private Map<String, Set<String>> buildServicesByMx() {
		Map<String, Set<String>> result = new HashMap<>();
		for (DomainInfo domain : _db.getDomains().values()) {
			String service = domain.getService();
			if (service == null) {
				continue;
			}
			
			for (String mx : domain.getMailServers()) {
				result.computeIfAbsent(mx, x -> new HashSet<>()).add(service);
			}
		}
		
		return result;
	}

	private Map<String, Set<String>> buildServicesByAddress() {
		Map<String, Set<String>> result = new HashMap<>();
		for (DomainInfo domain : _db.getDomains().values()) {
			String service = domain.getService();
			if (service == null) {
				continue;
			}
			
			for (String mx : domain.getMailServers()) {
				MxInfo mxInfo = _db.getMailServers().get(mx);
				
				for (String address : mxInfo.getAddresses()) {
					result.computeIfAbsent(address, x -> new HashSet<>()).add(service);
				}
			}
		}
		return result;
	}
	
	private void updateClassifications() {
		updateClassifications(_db);
	}

	private void updateClassifications(DB db) {
		// Reset mx classification.
		for (MxInfo mx : db.getMailServers().values()) {
			mx.setKind(Classification.UNKNOWN);
		}
		
		// Build mx classification from domain classification.
		for (DomainInfo domain : db.getDomains().values()) {
			for (String mx : domain.getMailServers()) {
				MxInfo mxInfo = db.getMailServers().get(mx);
				mxInfo.setKind(combine(mxInfo.getKind(), domain.getKind()));
			}
		}
	}

	private Map<String, Classification> buildAddressClassification() {
		Map<String, Classification> addressClassification = new HashMap<>();

		// Build address classification from mx classification.
		for (MxInfo mx : _db.getMailServers().values()) {
			for (String address : mx.getAddresses()) {
				addressClassification.put(address, combine(addressClassification.getOrDefault(address, Classification.UNKNOWN), mx.getKind()));
			}
		}
		
		return addressClassification;
	}

	private Classification combine(Classification x, Classification y) {
		if (y == Classification.UNKNOWN) {
			return x;
		}
		if (x == Classification.UNKNOWN) {
			return y;
		}
		if (x == y) {
			return x;
		}
		return Classification.MIXED;	}

	private Classification anyDisposable(Classification x, Classification y) {
		if (y == Classification.UNKNOWN) {
			return x;
		}
		if (x == Classification.UNKNOWN) {
			return y;
		}
		if (x == y) {
			return x;
		}
		if (x == Classification.DISPOSABLE) {
			return x;
		}
		if (y == Classification.DISPOSABLE) {
			return y;
		}
		return Classification.MIXED;
	}

	private DB _db;
	
	public MxResolver() throws IOException {
		initDb();
	}

	private void load(String fileName, Classification classification) throws IOException, SQLException {
		try {
			try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(new File(fileName)), StandardCharsets.UTF_8))) {
				String line;
				String service = null;
				while ((line = r.readLine()) != null) {
					if (line.startsWith("#")) {
						service = line.substring(1).trim();
						if (service.isEmpty()) {
							service = null;
						}
						continue;
					}
					
					String domain = line.trim().toLowerCase();
					if (domain.isEmpty()) {
						service = null;
						continue;
					}

					if (getDomain(domain) != null) {
						// Already present.
					} else {
						System.err.println("Analyzing domain: " + domain + (service != null ? " (" + service + ")" : ""));
						enterDomain(domain, service, classification);
					}
				}
			}

			updateClassifications();
		} finally {
			storeDb();
		}
	}

	private DomainInfo enterDomain(String domain, String service, Classification classification) throws TextParseException { 
		String normalizedDomain = domain.toLowerCase();
		
		DomainInfo domainInfo = createDomain(normalizedDomain, service, classification);
		fillFromDNS(normalizedDomain, domainInfo);
		storeDomain(normalizedDomain, domainInfo);
		return domainInfo;
	}

	private void fillFromDNS(String domain, DomainInfo domainInfo) throws TextParseException {
		Record[] records = new Lookup(domain, Type.MX).run();
		
		if (records == null) {
			// Domain is its own mail server.
			try {
				enterMx(domainInfo, domain);
			} catch (UnknownHostException ex) {
				domainInfo.setKind(Classification.DEAD);
				domainInfo.setHeuristics(Heuristics.NO_FALLBACK_MX);
			}
		} else {
			boolean alive = false;
			for (int i = 0; i < records.length; i++) {
				MXRecord mx = (MXRecord) records[i];
				String mailServer = mx.getTarget().toString(true).toLowerCase();
				
				try {
					enterMx(domainInfo, mailServer);
					alive = true;
				} catch (UnknownHostException ex) {
					// Ignore.
				}
			}
			if (!alive) {
				domainInfo.setKind(Classification.DEAD);
				domainInfo.setHeuristics(Heuristics.NO_RESOLVABLE_MX);
			}
		}
	}

	private DomainInfo getDomain(String domain) {
		return _db.getDomains().get(domain);
	}

	private DomainInfo createDomain(String domain, String service, Classification classification) {
		return DomainInfo.create().setService(service).setKind(classification);
	}

	private void storeDomain(String domain, DomainInfo domainInfo) {
		_db.putDomain(domain, domainInfo);
	}

	private void enterMx(DomainInfo domain, String mailServer) throws UnknownHostException {
		MxInfo mxInfo = _db.getMailServers().get(mailServer);
		if (mxInfo == null) {
			mxInfo = MxInfo.create();
			_db.getMailServers().put(mailServer, mxInfo);
			
			InetAddress[] addresses = Address.getAllByName(mailServer);
			for (InetAddress address : addresses) {
				String hostAddress = address.getHostAddress();
				
				mxInfo.addAddresse(hostAddress);
			}
		}
		
		// Found new mail server. 
		domain.getMailServers().add(mailServer);
	}

	private void initDb() throws IOException {
		File file = dbFile();
		if (file.exists()) {
			_db = loadDb(file);
		} else {
			_db = DB.create();
		}
	}

	private DB loadDb(File file) throws IOException, FileNotFoundException {
		try (JsonReader r = new JsonReader(new ReaderAdapter(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)))) {
			return DB.readDB(r);
		}
	}

	private File dbFile() {
		return new File("./fakedomain.json");
	}

	private void storeDb() throws IOException {
		writeTo(new FileOutputStream(dbFile()), _db);
	}

	private void writeTo(OutputStream out, DB obj) throws IOException {
		try (JsonWriter w = new JsonWriter(new WriterAdapter(new OutputStreamWriter(out, StandardCharsets.UTF_8)))) {
			w.setIndent("\t");
			
			obj.writeTo(w);
		}
	}

	private void resetDb() {
		_db = DB.create();
	}

}
