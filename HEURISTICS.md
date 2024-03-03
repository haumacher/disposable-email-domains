# Fake-mail detection heuristics

Manually collecting a list of fake-mail domains is a cumbersome task, since the fake-mail providers keep changing their domains to fight blocking. 
However, their web domain name is relatively stable, since this domain name is a valuable asset (e.g. due to its Google ranking). 
This suggests that manually collecting a list of fake-mail provider web sites and automatically deriving their mail domains is way more effective.

Some of the fake-mail services let the user chose the domain name for its fake e-mail address. 
In the easiest case, a select box with fake-mail domains is found on the web site of such fake mail providers that could be extracted automatically using a Selenium script.
But more professional fake-mail services protect their services from automatic querying. 

There may be several protective mechanisms:
* User cannot select the e-mail domain name. 
  The domain name is randomly chosen from a large list of domains. 
  The same request IP may always receive a fake-mail address from the same e-mail domain.
  This effectively prevents automatically collecting all e-mail domain names through an automatic job that repeatedly crawls the web site of the fake-mail provider.
* Creating a fake-mail address requires solving a strong CAPTCHA. 
  There is no simple way to automate the task of asking the service for fake-mail addresses to collect their domain names in a block-list.
* Traffic monitoring may block the users IP address from creating more fake-mail addresses, if an automatic lookup is done to often.
  Especially when running the task monitoring for new fake-mail domains of a certain service is run form a host with a static IP address.
* Headless browser detection may prevent automating the task of monitoring for new fake-mail domains of a certain provider at all.
   
However, manually creating some fake-mail addresses from a fake-mail provider is a relatively simple task.

## Detecting new fake-mail domains from a small set of training data

Let's assume we have a list of many fake-mail service providers with a small set of e-mail domains for each of these providers. 
This data can easily be collected manually.

### MX Records 

Technically, receiving e-mail for some domain name, requires to associate a SMTP server with that domain that is responsible for receiving e-mails for that domain.
When an e-mail is sent to `foobar@muell.xyz`, the sending server looks for a mail server that is responsible for receiving e-mails for the domain `muell.xyz`. 
This lookup is done by querying the domain name system for an MX record for the domain `muell.xyz`:

```
$ dig +nocomments +nocmd +noquestion +nostats +norrcomment muell.xyz MX
muell.xyz.		85	IN	MX	1 loti3.papierkorb.me.
```

This means, the MX record for `muell.xyz` points to the server `loti3.papierkorb.me` that is responsible for receiving mails for this domain. 
The server name `loti3.papierkorb.me` is associated with an IP address for actually establishing connections to that server:

```
$ dig +nocomments +nocmd +noquestion +nostats +norrcomment loti3.papierkorb.me
loti3.papierkorb.me.	273	IN	A	37.120.161.24
```

Both information, the mail server name and it's IP address point to the infrastructure used by the fake-mail service. 
If the fake-mail service is running its own servers, identifying all of its fake-mail domains is an easy task.
There is a good chance that the fake-mail service is using the same (or at least only a few) servers to handle all e-mail traffic for all used e-mail domains, since operating such infrastructure has associated cost.  
When identifying these servers from a small training data example of fake-mail domains used by a certain provider, all other fake-mail domains of the same provider can easily be identified because they are associated with the same infrastructure.   

However, there is no way to list all fake-mail domains of a certain provider, because the domain name system only offers information when being queried for a certain domain name. 
There is no way to list all domain names associated e.g. with a certain mail server.

### Whois database

Since fake-mail services often change their domain names, a domain that is relatively new is suspicious to belong to a disposable mail service.

```
$ whois aufu.de
...
Changed: 2024-02-05T18:25:57+01:00
...
```

### SURBL blacklist

There are so called black lists for domains that use the domain name system for checking. 

The blacklist https://www.surbl.org/ can be queried by looking up the corresponding domain name as prefix to the domain name of the black-list `.multi.surbl.org`.
Checking `opentrash.com` for inclusion into the black-list, the name `opentrash.com.multi.surbl.org` is resolved. 
If an answer is returned, the domain is contained in the black-list and the last octet of the IP address determines the reason for inclusion.
See https://www.surbl.org/lists for details.

```
$ dig +nocomments +nocmd +noquestion +nostats +norrcomment opentrash.com.multi.surbl.org
opentrash.com.multi.surbl.org. 163 IN	A	127.0.0.4
```

The `4` means the domain `opentrash.com` is included in the disposable mail domains blacklist. 


## When the heuristic does not work

There are several reasons, why the above heuristics is unable to safely detect fake-mail domains. 

### Cloud infrastructure

A fake-mail service may completely rely on cloud infrastructure provided by a large cloud service provider.
In such a case, the MX records of such a fake-mail domain point to the mail servers of the cloud provider:

```
$ dig +nocomments +nocmd +noquestion +nostats +norrcomment leechchannel.com MX
leechchannel.com.	3048	IN	MX	1 aspmx.l.google.com.
leechchannel.com.	3048	IN	MX	5 alt1.aspmx.l.google.com.
leechchannel.com.	3048	IN	MX	5 alt2.aspmx.l.google.com.
leechchannel.com.	3048	IN	MX	10 alt3.aspmx.l.google.com.
leechchannel.com.	3048	IN	MX	10 alt4.aspmx.l.google.com.
```

Here, Google mail servers are responsible for handling e-mail of the fake-mail domain `leechchannel.com` by the fake-mail provider `https://tmailor.com`.
Neither the MX records nor the IP addresses of the associated servers are a criterion for detecting other fake-mail domains of the same provider.

### Services proxying real e-mail providers

There are fake-mail services that provide users with e-mail addresses from regular e-mail providers such as `gmail.com`. 
E.g. `https://www.emailnator.com/` is able to generate temporary e-mail addresses from the Google gmail service.
Those addresses cannot be detected, not even from the e-mail domain name.   

### Users creating temporary e-mail addresses from real e-mail providers

Of cause, users can simple create a new e-mail address from a free e-mail provider, use this e-mail for registration and then simply forget the address. 
There is no means against that, too.

## Detecting dead domains

Fake-mail providers constantly allocate new domains and abandon old ones. 
When managing a list of fake-mail domains, removing dead domains is not really critical.
A dead domain cannot receive e-mail and therefore users will not use e-mail addresses from those domains. 
However, the domain could be re-allocated as regular domain. 
Keeping the domain on the block-list will prevent using e-mail addresses from such domain for registration.
To clean up the block list, e-mail domains could be dropped that

 * have no longer a resolvable MX record assigned, or 
 * that become assigned to a well-known domain reseller.

