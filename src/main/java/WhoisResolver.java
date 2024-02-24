import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.net.whois.WhoisClient;

import be.dnsbelgium.rdap.client.RDAPClient;

public class WhoisResolver {
	public static void main(String[] args) throws SocketException, IOException {
		new WhoisResolver().run();
	}
	
	Map<String, WhoisClient> clients = new HashMap();
	
	void run() throws IOException {
		String domain;
		try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(new File("disposable_email_blocklist.conf")), StandardCharsets.UTF_8))) {
			while ((domain = in.readLine()) != null) {
				Map<String, String> result = query(domain);
				String organization = result.get("Registrant Organization".toLowerCase());
				System.out.println(domain + "\t" + (organization == null ? "-" : organization));
			}
		}
	}

	private Map<String, String> query(String domain) throws SocketException, IOException {
		String server = WhoisClient.DEFAULT_HOST;
		Map<String, String> info = queryDirect(server, domain);
		
		String canonicalServer = info.get("Registrar WHOIS Server".toLowerCase());
		if (canonicalServer != null && !canonicalServer.equalsIgnoreCase(server)) {
			info = queryDirect(canonicalServer.toLowerCase(), domain);
		}
		return info;
	}

	private Map<String, String> queryDirect(String server, String domain) {
		Map<String, String> info;
		try {
			WhoisClient whois = getClient(server);
			String query = whois.query(domain);
			info = parse(query);
			return info;
		} catch (IOException e) {
			return Collections.emptyMap();
		}
	}

	private Map<String, String> parse(String domain) {
		HashMap result = new HashMap();
		for (String line : domain.split("\\r?\\n")) {
			int sepIdx = line.indexOf(':');
			if (sepIdx >= 0) {
				String key = line.substring(0, sepIdx).trim();
				String value = line.substring(sepIdx + 1).trim();
				result.put(key.toLowerCase(), value);
			}
		}
		return result;
	}

	private WhoisClient getClient(String server) throws SocketException, IOException {
		WhoisClient client = clients.get(server);
		if (client != null) {
			return client;
		}
		
		WhoisClient whois = new WhoisClient();
		whois.connect(server);
		clients.put(server, whois);
		return whois;
	}
}

// Query result from default server:
/**
   Domain Name: LAYMRO.COM
   Registry Domain ID: 2664027666_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.namesilo.com
   Registrar URL: http://www.namesilo.com
   Updated Date: 2024-01-25T07:33:30Z
   Creation Date: 2021-12-26T00:52:16Z
   Registry Expiry Date: 2024-12-26T00:52:16Z
   Registrar: NameSilo, LLC
   Registrar IANA ID: 1479
   Registrar Abuse Contact Email: abuse@namesilo.com
   Registrar Abuse Contact Phone: +1.4805240066
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.DNSOWL.COM
   Name Server: NS2.DNSOWL.COM
   Name Server: NS3.DNSOWL.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2024-02-07T16:37:28Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' ("VeriSign") Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. VeriSign does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to VeriSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
*/

/**
Domain Name: laymro.com
Registry Domain ID: 2664027666_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namesilo.com
Registrar URL: https://www.namesilo.com/
Updated Date: 2024-01-25T07:00:00Z
Creation Date: 2021-12-25T07:00:00Z
Registrar Registration Expiration Date: 2024-12-25T07:00:00Z
Registrar: NameSilo, LLC
Registrar IANA ID: 1479
Registrar Abuse Contact Email: abuse@namesilo.com
Registrar Abuse Contact Phone: +1.4805240066
Domain Status: clientTransferProhibited https://www.icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: PrivacyGuardian.org llc
Registrant Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Registrant City: Phoenix
Registrant State/Province: AZ
Registrant Postal Code: 85016
Registrant Country: US
Registrant Phone: +1.3478717726
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: pw-a894317db163687186941079bef44c3e@privacyguardian.org
Registry Admin ID: 
Admin Name: Domain Administrator
Admin Organization: PrivacyGuardian.org llc
Admin Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Admin City: Phoenix
Admin State/Province: AZ
Admin Postal Code: 85016
Admin Country: US
Admin Phone: +1.3478717726
Admin Phone Ext: 
Admin Fax: 
Admin Fax Ext: 
Admin Email: pw-a894317db163687186941079bef44c3e@privacyguardian.org
Registry Tech ID: 
Tech Name: Domain Administrator
Tech Organization: PrivacyGuardian.org llc
Tech Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Tech City: Phoenix
Tech State/Province: AZ
Tech Postal Code: 85016
Tech Country: US
Tech Phone: +1.3478717726
Tech Phone Ext: 
Tech Fax: 
Tech Fax Ext: 
Tech Email: pw-a894317db163687186941079bef44c3e@privacyguardian.org
Name Server: NS1.DNSOWL.COM
Name Server: NS1.DNSOWL.COM
Name Server: NS2.DNSOWL.COM
Name Server: NS3.DNSOWL.COM
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2024-02-07T07:00:00Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE AND TERMS OF USE: You are not authorized to access or query our WHOIS
database through the use of high-volume, automated, electronic processes. The
Data in our WHOIS database is provided for information purposes only, and to
assist persons in obtaining information about or related to a domain name
registration record. We do not guarantee its accuracy. By submitting a WHOIS
query, you agree to abide by the following terms of use: You agree that you may
use this Data only for lawful purposes and that under no circumstances will you
use this Data to: (1) allow, enable, or otherwise support the transmission of
mass unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes that
apply to us (or our computer systems). The compilation, repackaging,
dissemination or other use of this Data is expressly prohibited without our
prior written consent. We reserve the right to terminate your access to the
WHOIS database at our sole discretion, including without limitation, for
excessive querying of the WHOIS database or for failure to otherwise abide by
this policy. We reserve the right to modify these terms at any time.

Domains - cheap, easy, and secure at NameSilo.com

https://www.namesilo.com

Register your domain now at www.NameSilo.com - Domains. Cheap, Fast and Secure
*/