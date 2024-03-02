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

