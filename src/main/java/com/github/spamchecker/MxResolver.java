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
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.Set;

import org.xbill.DNS.Address;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import com.github.spamchecker.model.Classification;
import com.github.spamchecker.model.Index;
import com.github.spamchecker.model.Domain;
import com.github.spamchecker.model.DomainData;
import com.github.spamchecker.model.DomainInfo;
import com.github.spamchecker.model.Heuristics;
import com.github.spamchecker.model.Host;
import com.github.spamchecker.model.MailServer;
import com.github.spamchecker.model.MxData;
import com.github.spamchecker.model.MxInfo;
import com.github.spamchecker.model.Service;
import com.github.spamchecker.model.Storage;

import de.haumacher.msgbuf.data.DataObject;
import de.haumacher.msgbuf.json.JsonReader;
import de.haumacher.msgbuf.json.JsonWriter;
import de.haumacher.msgbuf.server.io.ReaderAdapter;
import de.haumacher.msgbuf.server.io.WriterAdapter;

public class MxResolver {
	
	public static void main(String[] args) throws IOException, SQLException {
		new MxResolver().run(args);
	}
	
	private String _dbFile = "./fakedomain.json";

	private Index _db;

	private String _outFile = "-";

	public MxResolver() throws IOException {
		loadDb();
	}

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
				String domain = args[++n];
				DomainData result = query(domain);
				System.out.println(domain + ": " + result);
				break;
			case "classify": 
				classify(args[++n]);
				break;
			case "load": 
				load(args[++n]);
				break;
			case "load-disposable": 
				load(args[++n], Classification.DISPOSABLE);
				break;
			case "load-alias": 
				load(args[++n], Classification.ALIAS);
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
				_dbFile = args[++n];
				break;
			case "load-db":
				loadDb();
				break;
			case "store-db":
				storeDb();
				break;
			case "load-raw-from":
				_dbFile = args[++n];
				_db = loadDbRaw(new File(_dbFile));
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
		for (Entry<String, DomainData> entry : _db.getDomains().entrySet()) {
			if (entry.getValue().getKind() == Classification.DISPOSABLE) {
				result.add(entry.getKey());
			}
		}
		Collections.sort(result);
		for (String domain : result) {
			System.out.println(domain);
		}
	}

	private void load(String fileName) throws IOException {
		XRefIndex index = buildIndex(_db);

		List<DomainData> domains = new ArrayList<>();
		try (BufferedReader r = new BufferedReader(new InputStreamReader("-".equals(fileName) ? System.in : new FileInputStream(new File(fileName)), StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.startsWith("#")) {
					continue;
				}
				
				String domain = line.trim().toLowerCase();
				if (domain.isEmpty()) {
					continue;
				}

				DomainData info = query(domain, index);
				System.err.println(domain + ": " + info);
				domains.add(info);
			}
		}
		
		updateClassifications(_db);
	}
	
	private void classify(String fileName) throws IOException {
		Index db = Index.create();
		classify(db, fileName);
		writeTo(outStream(), toStorage(db));
	}

	private void classify(Index db, String fileName) throws IOException, TextParseException, FileNotFoundException {
		XRefIndex index = buildIndex(_db);

		try (BufferedReader r = new BufferedReader(new InputStreamReader("-".equals(fileName) ? System.in : new FileInputStream(new File(fileName)), StandardCharsets.UTF_8))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.startsWith("#")) {
					continue;
				}
				
				String domain = line.trim().toLowerCase();
				if (domain.isEmpty()) {
					continue;
				}

				DomainData info = query(domain, index);
				System.err.println(domain + ": " + info);
				db.getDomains().put(domain, info);
			}
		}
		
		// Copy mail server section to result.
		for (DomainData domain : db.getDomains().values()) {
			for (String mx : domain.getMailServers()) {
				db.getMailServers().put(mx, _db.getMailServers().get(mx));
			}
		}
		updateClassifications(db);
	}

	private OutputStream outStream() throws FileNotFoundException {
		return "-".equals(_outFile) ? System.out : new FileOutputStream(new File(_outFile));
	}

	private DomainData query(String domain) throws TextParseException {
		XRefIndex index = buildIndex(_db);
		return query(domain, index);
	}

	private static XRefIndex buildIndex(Index db) {
		Map<String, Classification> addressClassification = buildAddressClassification(db);
		Map<String, Set<String>> serviceByMx = buildServicesByMx(db);
		Map<String, Set<String>> serviceByAddress = buildServicesByAddress(db);
		
		return new XRefIndex(addressClassification, serviceByMx, serviceByAddress);
	}

	private DomainData query(String domain, XRefIndex index) throws TextParseException {
		DomainData existingDomain = getDomain(domain);
		if (existingDomain != null) {
			return existingDomain;
		}
		
		DomainData newDomain = enterDomain(domain, null, Classification.UNKNOWN);
		
		Classification mxGuess = Classification.UNKNOWN;
		Classification addressGuess = Classification.UNKNOWN;
		Set<String> mxServices = new HashSet<>();
		Set<String> addressServices = new HashSet<>();
		for (String mx : newDomain.getMailServers()) {
			MxData mxInfo = _db.getMailServers().get(mx);
			mxGuess = anyDisposable(mxGuess, mxInfo.getKind());

			for (String address : mxInfo.getAddresses()) {
				addressGuess = anyDisposable(addressGuess, index.addressClassification.getOrDefault(address, Classification.UNKNOWN));
				
				addressServices.addAll(index.serviceByAddress.getOrDefault(address, Collections.emptySet()));
			}
			
			mxServices.addAll(index.serviceByMx.getOrDefault(mx, Collections.emptySet()));
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

	private void setService(DomainData newDomain, Set<String> mxServices) {
		if (mxServices.size() == 1) {
			newDomain.setService(mxServices.iterator().next());
		} else {
			newDomain.setPotentialServices(sorted(mxServices));
		}
	}

	private static ArrayList<String> sorted(Collection<String> services) {
		ArrayList<String> result = new ArrayList<>(services);
		Collections.sort(result);
		return result;
	}

	private static Map<String, Set<String>> buildServicesByMx(Index db) {
		Map<String, Set<String>> result = new HashMap<>();
		for (DomainData domain : db.getDomains().values()) {
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

	private static Map<String, Set<String>> buildServicesByAddress(Index db) {
		Map<String, Set<String>> result = new HashMap<>();
		for (DomainData domain : db.getDomains().values()) {
			String service = domain.getService();
			if (service == null) {
				continue;
			}
			
			for (String mx : domain.getMailServers()) {
				MxData mxInfo = db.getMailServers().get(mx);
				
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

	private void updateClassifications(Index db) {
		// Reset mx classification.
		for (MxData mx : db.getMailServers().values()) {
			mx.setKind(Classification.UNKNOWN);
		}
		
		// Build mx classification from domain classification.
		for (DomainData domain : db.getDomains().values()) {
			for (String mx : domain.getMailServers()) {
				MxData mxInfo = db.getMailServers().get(mx);
				mxInfo.setKind(combine(mxInfo.getKind(), domain.getKind()));
			}
		}
	}

	private static Map<String, Classification> buildAddressClassification(Index db) {
		Map<String, Classification> addressClassification = new HashMap<>();

		// Build address classification from mx classification.
		for (MxData mx : db.getMailServers().values()) {
			for (String address : mx.getAddresses()) {
				addressClassification.put(address, combine(addressClassification.getOrDefault(address, Classification.UNKNOWN), mx.getKind()));
			}
		}
		
		return addressClassification;
	}

	private static Classification combine(Classification x, Classification y) {
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

	private DomainData enterDomain(String domain, String service, Classification classification) throws TextParseException { 
		String normalizedDomain = domain.toLowerCase();
		
		DomainData domainInfo = createDomain(normalizedDomain, service, classification);
		fillFromDNS(normalizedDomain, domainInfo);
		storeDomain(normalizedDomain, domainInfo);
		return domainInfo;
	}

	private void fillFromDNS(String domain, DomainData domainInfo) throws TextParseException {
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

	private DomainData getDomain(String domain) {
		return _db.getDomains().get(domain);
	}

	private DomainData createDomain(String domain, String service, Classification classification) {
		return DomainInfo.create().setService(service).setKind(classification);
	}

	private void storeDomain(String domain, DomainData domainInfo) {
		_db.putDomain(domain, domainInfo);
	}

	private void enterMx(DomainData domain, String mailServer) throws UnknownHostException {
		MxData mxInfo = _db.getMailServers().get(mailServer);
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

	private File dbFile() {
		return new File(_dbFile);
	}

	private void loadDb() throws IOException {
		File file = dbFile();
		if (file.exists()) {
			_db = loadDb(file);
		} else {
			_db = Index.create();
		}
	}

	private void storeDb() throws IOException {
		File dbFile = dbFile();
		
		File tmp = File.createTempFile(dbFile.getName(), "", dbFile.getParentFile());
		writeTo(new FileOutputStream(tmp), toStorage(_db));

		File backup = new File(dbFile.getParentFile(), dbFile.getName() + "~");
		dbFile.renameTo(backup);

		tmp.renameTo(dbFile);
		backup.delete();
	}

	private Index loadDb(File file) throws IOException, FileNotFoundException {
		try (JsonReader r = new JsonReader(new ReaderAdapter(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)))) {
			return toDb(Storage.readStorage(r));
		}
	}

	private Index loadDbRaw(File file) throws IOException, FileNotFoundException {
		try (JsonReader r = new JsonReader(new ReaderAdapter(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)))) {
			return Index.readIndex(r);
		}
	}
	
	private Index toDb(Storage storage) {
		return Index.create()
			.setDomains(storage.getDomains().stream().collect(Collectors.toMap(d -> d.getName(), d -> d)))
			.setMailServers(storage.getMailServers().stream().collect(Collectors.toMap(m -> m.getName(), m -> m)));
	}

	private Storage toStorage(Index db) {
		return xref(Storage.create()
			.setDomains(db.getDomains()
				.entrySet()
				.stream()
				.map(entry -> Domain.create()
					.setName(entry.getKey())
					.setHeuristics(entry.getValue().getHeuristics())
					.setKind(entry.getValue().getKind())
					.setMailServers(entry.getValue().getMailServers().stream().sorted().collect(Collectors.toList()))
					.setPotentialServices(entry.getValue().getPotentialServices().stream().sorted().collect(Collectors.toList()))
					.setService(entry.getValue().getService()))
				.sorted((x, y) -> x.getName().compareTo(y.getName()))
				.collect(Collectors.toList()))
			.setMailServers(db.getMailServers()
				.entrySet()
				.stream()
				.map(entry -> MailServer.create()
					.setName(entry.getKey())
					.setAddresses(entry.getValue().getAddresses().stream().sorted().collect(Collectors.toList()))
					.setKind(entry.getValue().getKind()))
				.sorted((x, y) -> x.getName().compareTo(y.getName()))
				.collect(Collectors.toList())));
	}

	private Storage xref(Storage storage) {
		Map<String, MailServer> mailServerByName = storage.getMailServers().stream().collect(Collectors.toMap(s -> s.getName(), s -> s));
		
		Map<String, Service> serviceByName = new HashMap<>();
		Map<String, Set<String>> domainsByAddress = new HashMap<>();
		Map<String, Set<String>> domainsByMx = new HashMap<>();
		for (Domain domain : storage.getDomains()) {
			// Add domain to service.
			String serviceName = domain.getService();
			if (serviceName != null) {
				Service service = serviceByName.computeIfAbsent(serviceName, name -> Service.create().setName(name));
				service.getDomains().add(domain.getName());
				
				for (String mailServer : domain.getMailServers()) {
					MailServer host = mailServerByName.get(mailServer);
					host.addService(serviceName);

					service.getAddresses().addAll(host.getAddresses());
				}
			}
			
			// Add domain to potential service.
			for (String potentialServiceName : domain.getPotentialServices()) {
				Service potentialService = serviceByName.computeIfAbsent(potentialServiceName, name -> Service.create().setName(name));
				potentialService.getDomains().add(domain.getName());

				for (String mailServer : domain.getMailServers()) {
					MailServer host = mailServerByName.get(mailServer);
					host.addService(potentialServiceName);
					
					potentialService.getAddresses().addAll(host.getAddresses());
				}
			}
			
			for (String mailServer : domain.getMailServers()) {
				MailServer mx = mailServerByName.get(mailServer);
				
				domainsByMx.computeIfAbsent(mx.getName(), x -> new HashSet<>()).add(domain.getName());
				
				for (String address : mx.getAddresses()) {
					domainsByAddress.computeIfAbsent(address, x -> new HashSet<>()).add(domain.getName());
				}
			}
		}
		
		Map<String, Set<String>> mxByAddress = new HashMap<>();
		Map<String, Set<String>> servicesByAddress = new HashMap<>();
		for (MailServer mx : storage.getMailServers()) {
			mx.setDomains(sorted(domainsByMx.getOrDefault(mx.getName(), Collections.emptySet())));
			
			for (String service : mx.getServices()) {
				// Add mail server to service.
				serviceByName.computeIfAbsent(service, name -> Service.create().setName(name)).getMailServers().add(mx.getName());
			}
			
			for (String address : mx.getAddresses()) {
				// Add service to address;
				servicesByAddress.computeIfAbsent(address, x -> new HashSet<>()).addAll(mx.getServices());
				mxByAddress.computeIfAbsent(address, x -> new HashSet<>()).add(mx.getName());
			}
		}
		
		storage.setServices(
			serviceByName.values().stream().sorted(Comparator.comparing(s -> s.getName())).collect(Collectors.toList()));
		
		storage.setHosts(
			servicesByAddress.entrySet()
				.stream()
				.map(e -> Host.create()
					.setAddress(e.getKey())
					.setServices(sorted(e.getValue()))
					.setDomains(sorted(domainsByAddress.getOrDefault(e.getKey(), Collections.emptySet())))
					.setMailServers(sorted(mxByAddress.getOrDefault(e.getKey(), Collections.emptySet()))))
				.sorted(Comparator.comparing(h -> h.getAddress()))
				.collect(Collectors.toList()));
		
		return sort(storage);
	}

	private Storage sort(Storage storage) {
		for (MailServer server : storage.getMailServers()) {
			server.setServices(sorted(server.getServices()));
			server.setAddresses(sorted(server.getAddresses()));
		}

		for (Domain domain : storage.getDomains()) {
			domain.setMailServers(sorted(domain.getMailServers()));
			domain.setPotentialServices(sorted(domain.getPotentialServices()));
		}

		for (Host host : storage.getHosts()) {
			host.setMailServers(sorted(host.getMailServers()));
			host.setServices(sorted(host.getServices()));
		}
		
		for (Service service : storage.getServices()) {
			service.setAddresses(sorted(service.getAddresses()));
			service.setDomains(sorted(service.getDomains()));
			service.setMailServers(sorted(service.getMailServers()));
		}
		
		return storage;
	}

	private List<? extends String> sorted(List<String> s) {
		return s.stream().sorted().distinct().collect(Collectors.toList());
	}

	private void writeTo(OutputStream out, DataObject obj) throws IOException {
		try (JsonWriter w = new JsonWriter(new WriterAdapter(new OutputStreamWriter(out, StandardCharsets.UTF_8)))) {
			w.setIndent("\t");
			
			obj.writeTo(w);
		}
	}

	private void resetDb() {
		_db = Index.create();
	}

}
