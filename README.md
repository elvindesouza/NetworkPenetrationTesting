<!-- look up stages of penetration test and organize according to that
alternatively, use order of kali linux xdg-menu to organize -->
<!-- get nessus scans in repo -->
<!-- Security Testing-burpsuite nessus openVAS(another md for this?) metasploit nmap wireshark -->

# Reconnaissance

if someone were to gain access to the network one way or the other, the first thing they'd do would be enumerating and mapping the network. However, the methodology of the entire process would be considered **White Box Testing**

# Network Discovery

## Nmap

A SYN(stealth) scan can be performed, preferably with the OS detection flag enabled

![](nmapdiscover.png)

After enumerating hosts, you can craft a scan individually based on the host type

![](nmaptargeted.png)

## Netdiscover

![](netdiscoverhelp.png)
![](netdiscover.png)

## Nessus

<!-- After the setup, the first thing you want to run is a Host Discovery Scan -->

After seeing all the hosts on the network, you start a basic network scan on all the hosts. It will take some time to complete, based on the operating system and number of hosts
![](hostdiscovery.png)

## SQLi

just copy from google doc

## John the Ripper

In the case that the intruder gains physical access to the computer or exploits a service with elevated permissions, he might go for the `/etc/shadow` file containing information about users and accompanying passwords on the system.

```
┌──(user@user)-[~]
└─$ s tail /etc/shadow
beef-xss:*:19030:0:99999:7:::
king-phisher:*:19030:0:99999:7:::
_caldera:*:19030:0:99999:7:::
user:$y$j9T$znRa/I4zvH8rjS/QbrhiL/$KBpcdTDvskDWYXYHLvSZpIkvFjLFbb9PRNra/v4ER1/:19151:0:99999:7:::
nvpd:*:19041:0:99999:7:::
cntlm:!:19134::::::
_sentrypeer:!:19134::::::
gpsd:!:19134::::::
_juice:!:19134::::::
_dvwa:!:19134::::::
```

Using the `unshadow` command(it is supplied with `John`),
combine the `/etc/passwd` and `/etc/shadow` files so that they can be cracked with John

![](unshadow.png)
![](john.png)

## Wireshark

## BurpSuite

## Nikto

## Metasploit/Armitage

## Canarytokens(Honeypot)

##

# Remediation


Resist a possibly SYN flood attack by using **SYN cookies**

_more details are covered in my subsequent project, where I used the results from this process to harden systems on the same network_

netcat
netstat
