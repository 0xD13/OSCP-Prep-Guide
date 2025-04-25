# Codo

### Scan ports with nmap

```
nmap -sC -sV -A 192.168.125.23 -p- -v -o target_nmap.txt

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: All topics | CODOLOGIC
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

### Check the web service on port 80
![](/writeups/screenshot/Screenshot%202025-04-25%20at%2010.15.43.png)

Logged in using default credentials `admin/admin`

Check the service version, is **Codoforum**

Search exploits
```
┌──(kali㉿kali)-[~/Desktop/PG/Codo]
└─$ searchsploit codoforum
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CodoForum 2.5.1 - Arbitrary File Download                                                                                | php/webapps/36320.txt
CodoForum 3.2.1 - SQL Injection                                                                                          | php/webapps/40150.txt
CodoForum 3.3.1 - Multiple SQL Injections                                                                                | php/webapps/37820.txt
CodoForum 3.4 - Persistent Cross-Site Scripting                                                                          | php/webapps/40015.txt
Codoforum 4.8.3 - 'input_txt' Persistent Cross-Site Scripting                                                            | php/webapps/47886.txt
Codoforum 4.8.3 - Persistent Cross-Site Scripting                                                                        | php/webapps/47876.txt
CodoForum v5.1 - Remote Code Execution (RCE)                                                                             | php/webapps/50978.py
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
I tried the `50978.py` exploit for CodoForum v5.1 RCE, but the POC script failed due to errors

try to upload reverseshell manually.
1. I added .php to the "Allowed Upload Types" in the settings.
2. I uploaded a PHP reverse shell via the "Upload logo for your forum" feature.
![](/writeups/screenshot/Screenshot%202025-04-25%20at%2013.08.14.png)

get the reverse shell but no `local.txt`, try to get `proof.txt`

### Privilege Escalation

I ran linpeas.sh to identify privilege escalation vulnerabilities.
![](/writeups/screenshot/Screenshot%202025-04-25%20at%2013.11.56.png)
Using a password disclosed by `linpeas.sh` in a configuration file, I logged in as root with su and retrieved `proof.txt`