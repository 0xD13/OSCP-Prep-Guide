# OSCP-Prep-Guide
A collection of labs, tools, and study materials for OSCP exam preparation. Includes practice environments, scripts, and resources for enumeration, exploitation, and privilege escalation to help master penetration testing skills.

## Tool

### Enumeration

- [enum4linux](https://www.kali.org/tools/enum4linux/): a tool for enumerating information from Windows and Samba systems

### Privilege Escalation

- [GTFOBins](https://gtfobins.github.io/): list of Unix binaries which can escalate privileges
- [Linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS): search for possible paths to escalate privileges on Linux
- [Winpeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS): search for possible paths to escalate privileges on Windows
- [Penelope](https://github.com/brightio/penelope): reverse shell

### Password Crack

- [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit/): A modified version of the passing-the-hash tool collection
- [Hydra](https://www.kali.org/tools/hydra/): Hydra is a parallelized login cracker which supports numerous protocols to attack
- [john the ripper](https://www.openwall.com/john/): John the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems

### Vulnerability Exploit

- [Metasploit](https://github.com/rapid7/metasploit-framework)

## Walkthrough Labs

### TryHackMe

#### Web attack and SQL injection
- [X] [[Easy] Walking An Application](https://tryhackme.com/room/walkinganapplication)
- [X] [[Easy] Web Enumeration](https://tryhackme.com/room/webenumerationv2)
- [X] [[Medium] SQL Injection](https://tryhackme.com/room/sqlinjectionlm)
- [X] [[Easy] SQL Injection Lab](https://tryhackme.com/room/sqlilab)
- [X] [[Easy] Authentication Bypass](https://tryhackme.com/jr/authenticationbypass)
- [X] [[Easy] IDOR](https://tryhackme.com/jr/idor)
- [X] [[Easy] SSRF](https://tryhackme.com/jr/ssrfqi)
- [X] [[Medium] File Inclusion](https://tryhackme.com/room/fileinc)
- [X] [[Easy] Intro to Cross-site Scripting](https://tryhackme.com/room/xss)
- [X] [[Easy] Command Injection](https://tryhackme.com/room/oscommandinjection)
- [X] [[Easy] Upload Vulnerabilities](https://tryhackme.com/jr/uploadvulns)
- [X] [[Info] Bypass Disable Functions](https://tryhackme.com/room/bypassdisablefunctions)

#### Linux Privilege Escalation
- [X] [[Easy] Linux: Local Enumeration](https://tryhackme.com/room/lle)
- [X] [[Easy] Enumeration](https://tryhackme.com/room/enumerationpe)
- [X] [[Medium] Linux PrivEsc](https://tryhackme.com/room/linuxprivesc) 
- [X] [[Medium] Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)
- [X] [[Info] Sudo Security Bypass](https://tryhackme.com/room/sudovulnsbypass)
- [X] [[Easy] Common Linux Privesc
](https://tryhackme.com/room/commonlinuxprivesc)
- [X] [[Easy] Vulnversity](https://tryhackme.com/room/vulnversity)
- [X] [[Easy] Basic Pentesting](https://tryhackme.com/room/basicpentestingjt)
- [X] [[Easy] Bolt](https://tryhackme.com/room/bolt)

#### Windows Privilege Escalation
- [X] [[Easy] Enumeration](https://tryhackme.com/room/enumerationpe)
- [X] [[Medium] Windows PrivEsc](https://tryhackme.com/room/windows10privesc)
- [X] [[Medium]Windows PrviEsc Arena](https://tryhackme.com/room/windowsprivesc20)
- [X] [[Easy] Vulnerabilities 101](https://tryhackme.com/jr/vulnerabilities101)
- [X] [[Easy] Exploit Vulnerabilities](https://tryhackme.com/jr/exploitingavulnerabilityv2)
- [X] [[Easy] Vulnerability Capstone](https://tryhackme.com/jr/vulnerabilitycapstone)
- [X] [[Easy] Intro PoC Scripting](https://tryhackme.com/room/intropocscripting)
- [ ] [Wreath](https://tryhackme.com/room/wreath)

#### Windows Active Directory Attack
- [ ] [Active Directory Basics](https://tryhackme.com/room/winadbasics)
- [ ] [Attacktive Directory](https://tryhackme.com/room/attacktivedirectory)
- [ ] [Attacking Kerberos](https://tryhackme.com/room/attackingkerberos)
- [ ] [Breaching Active Directory](https://tryhackme.com/room/breachingad)
- [ ] [AD Enumeration](https://tryhackme.com/room/adenumeration)
- [ ] [Lateral Movement and Pivoting](https://tryhackme.com/jr/lateralmovementandpivoting)
- [ ] [Exploiting Active Directory](https://tryhackme.com/room/exploitingad)
- [ ] [Post-Exploitation Basics](https://tryhackme.com/room/postexploit)
- [ ] [HoloLive](https://tryhackme.com/room/hololive)
- [ ] [Throwback Network Labs Attacking Windows Active Directory](https://tryhackme.com/network/throwback)

### Hack The Box
- [ ] [Network Enumeration with Nmap](https://academy.hackthebox.com/course/preview/network-enumeration-with-nmap)
- [ ] [FootPrinting](https://academy.hackthebox.com/course/preview/footprinting)
- [ ] [Attacking Common Services](https://academy.hackthebox.com/course/preview/attacking-common-services)
- [ ] [Information Gathering Web Edition](https://academy.hackthebox.com/course/preview/information-gathering---web-edition)
- [ ] [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications)
- [ ] [Web Attacks](https://academy.hackthebox.com/course/preview/web-attacks)
- [ ] [File Inclusion](https://academy.hackthebox.com/course/preview/file-inclusion)
- [ ] [Abusing HTTP Misconfigurations](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations)
- [ ] [HTTP Attacks](https://academy.hackthebox.com/course/preview/http-attacks)
- [ ] [SQL Injection Fundamentals](https://academy.hackthebox.com/course/preview/sql-injection-fundamentals)
- [ ] [Blind SQL Injection](https://academy.hackthebox.com/course/preview/blind-sql-injection)
- [ ] [Advanced SQL Injection](https://academy.hackthebox.com/course/preview/advanced-sql-injections)
- [ ] [Using Web Proxies](https://academy.hackthebox.com/course/preview/using-web-proxies)
- [ ] [Attacking Web Applications with ffuf](https://academy.hackthebox.com/course/preview/attacking-web-applications-with-ffuf)
- [ ] [Session Security](https://academy.hackthebox.com/course/preview/session-security)
- [ ] [Attacking Authentication Mecanism](https://academy.hackthebox.com/course/preview/attacking-authentication-mechanisms)
- [ ] [Web Service & API Attacks](https://academy.hackthebox.com/course/preview/web-service--api-attacks)
- [ ] [Broken Authentication](https://academy.hackthebox.com/course/preview/broken-authentication)
- [ ] [File Upload Attacks](https://academy.hackthebox.com/course/preview/file-upload-attacks)
- [ ] [Whitebox Pentesting 101: Command Injection](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection)
- [ ] [Command Injections](https://academy.hackthebox.com/course/preview/command-injections)
- [ ] [Cross-Site Scripting (XSS)](https://academy.hackthebox.com/course/preview/cross-site-scripting-xss)
- [ ] [Server-Side Attacks](https://academy.hackthebox.com/course/preview/server-side-attacks)
- [ ] [Introduction to NoSQL Injection](https://academy.hackthebox.com/course/preview/introduction-to-nosql-injection)
- [ ] [Introduction to Deserialization Attacks](https://academy.hackthebox.com/course/preview/introduction-to-deserialization-attacks)
- [ ] [Linux Privilege Escalation](https://academy.hackthebox.com/course/preview/linux-privilege-escalation) 
- [ ] [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation)
- [ ] [File Transfers](https://academy.hackthebox.com/course/preview/file-transfers)
- [ ] [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/course/preview/pivoting-tunneling-and-port-forwarding)
- [ ] [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory)
- [ ] [Active Directory Enumeration Attacks](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks)
- [ ] [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap)
- [ ] [Active Directory PowerView](https://academy.hackthebox.com/course/preview/active-directory-powerview)
- [ ] [Active Directory BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound)
- [ ] [Kerberos Attacks](https://academy.hackthebox.com/course/preview/kerberos-attacks)
- [ ] [Using crackmapexec](https://academy.hackthebox.com/course/preview/using-crackmapexec)
- [ ] [Password Attacks](https://academy.hackthebox.com/course/preview/password-attacks)
- [ ] [Attacking Enterprise Networks](https://academy.hackthebox.com/course/preview/attacking-enterprise-networks)
- [ ] [Documentation & Reporting](https://academy.hackthebox.com/course/preview/documentation--reporting)

## Challenge Labs 

### Proving Grounds Play

#### Linux Box

- [ ] [Amaterasu]()
- [ ] [BBScute]()
- [ ] [Blogger]()
- [ ] [DC-9]()
- [ ] [DriftingBlue6]()
- [ ] [eLection]()
- [ ] [FunboxEasyEnum]()
- [ ] [Gaara]()
- [ ] [InsanityHosting]()
- [ ] [Loly]()
- [ ] [Monitoring]()
- [ ] [Potato]()
- [ ] [Stapler]()

### Proving Grounds Practice

#### Linux Box

- [ ] [Apex]()
- [ ] [Astronaut]()
- [ ] [BitForge]()
- [ ] [Blackgate]()
- [ ] [Boolean]()
- [ ] [Bratarina]()
- [ ] [Bullybox]()
- [ ] [ClamAV]()
- [ ] [Clue]()
- [ ] [Cockpit]()
- [ ] [Codo]()
- [ ] [Crane]()
- [ ] [Exfiltrated]()
- [ ] [Extplorer]()
- [ ] [Fanatastic]()
- [ ] [Fired]()
- [ ] [Flu]()
- [ ] [Hawat]()
- [ ] [Hetemit]()
- [ ] [Hub]()
- [ ] [Hunit]()
- [ ] [Image]()
- [ ] [Jordak]()
- [ ] [Lavita]()
- [ ] [law]()
- [ ] [Levram]()
- [ ] [Mantis]()
- [ ] [Marketing]()
- [ ] [Mzeeav]()
- [ ] [Nibbles]()
- [ ] [Nukem]()
- [ ] [Ochima]()
- [ ] [Payday]()
- [ ] [PC]()
- [ ] [Pebbles]()
- [ ] [Pelican]()
- [ ] [Peppo]()
- [ ] [Plum]()
- [ ] [Postfish]()
- [ ] [Press]()
- [ ] [PyLoader]()
- [ ] [QuackerJack]()
- [ ] [Readys]()
- [ ] [Roquefort]()
- [ ] [RubyDome]()
- [ ] [Scrutiny]()
- [ ] [Snookums]()
- [ ] [Sorcerer]()
- [ ] [SPX]()
- [ ] [Sybaris]()
- [ ] [Twiggy]()
- [ ] [Vmdak]()
- [ ] [Walla]()
- [ ] [WallpaperHub]()
- [ ] [Wombo]()
- [ ] [Xposedapi]()
- [ ] [Zab]()
- [ ] [ZenPhoto]()
- [ ] [Zipper]()

#### Windows Box
- [ ] [Algernon]()
- [ ] [Authby]()
- [ ] [Billyboss]()
- [ ] [Craft]()
- [ ] [DVR4]()
- [ ] [Fish]()
- [ ] [Helpdesk]()
- [ ] [Hepet]()
- [ ] [Hutch]()
- [ ] [Internal]()
- [ ] [Jacko]()
- [ ] [Kevin]()
- [ ] [MedJed]()
- [ ] [Mice]()
- [ ] [Monster]()
- [ ] [Nickel]()
- [ ] [Resourced]()
- [ ] [Shenzi]()
- [ ] [Slort]()
- [ ] [Squid]()

#### Windows Active Directory
- [ ] [Access]()
- [ ] [Heist]()
- [ ] [Hokkaido]()
- [ ] [Hutch]()
- [ ] [Nagoya]()
- [ ] [Resourced]()
- [ ] [Vault]()

#### Try Harder
- [ ] [Nagoya [Windows]]()
- [ ] [Osaka [Windows]]()
- [ ] [ProStore [Linux]]()
- [ ] [RPC1 [Linux]]()
- [ ] [Symbolic [Windows]]()
- [ ] [Upsploit [Linux]]()
- [ ] [Validator [Linux]]()
- [ ] [GLPI [Linux]]()
- [ ] [Marshalled [Linux]]()
- [ ] [Educated [Linux]]()
- [ ] [Kyoto [Windows Buffer Overflow]]()
- [ ] [Nara [Windows Active Directory]]()

### Vlunlab

#### Linux Box

- [ ] [Bamboo]()
- [ ] [Build]()
- [ ] [Data]()
- [ ] [Dump]()
- [ ] [Feedback]()
- [ ] [Forgotten]()
- [ ] [Sync]()

#### Windows Box

#### Windows Active Directory

#### Try Harder

## Cheat Sheet

### Linux Command
Check user's sudo permissions
```shell
sudo -l
```
Find the file
```shell
find / -iname "flag.txt" 2>/dev/null
```
Find all SUID file
```shell
find / -perm -u=s -type f 2>/dev/null
```
Find all the SUID/SGID executables
```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
### Nmap

Enumerate the users on a remote Windows system
```
nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
```


### SQL injection

#### Database info discovery
Version
```shell
# Microsoft or MySQL
@@version 
# PostgreSQL
version()
# SQLite
sqlite_version()
```

Show Tables
``` sql
-- SQLite
SELECT name FROM sqlite_master WHERE type = "table"
```
#### UNION attacks
Example
```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
Determining the number of columns required
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc. 
```
Finding columns with a useful data type
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

### Password Cracker

#### .ssh
The keys need to be read-writable only by you:
```
chmod 600 ~/.ssh/id_rsa
```

#### pth-winexe
```
pth-winexe -U 'admin%password123' //10.10.119.24 cmd.exe
```

## Reference
- https://github.com/rodolfomarianocy/OSCP-Tricks-2023
- https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt
- https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8
- https://portswigger.net/
- https://tryhackme.com/
