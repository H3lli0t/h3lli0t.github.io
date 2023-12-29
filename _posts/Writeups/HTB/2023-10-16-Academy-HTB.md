---
title: "HackTheBox | Academy"
layout: post
date: 2023-10-16 17:00
tag: 
- HackTheBox
- Linux
- Pentesting
- Machines
- Academy
- Easy
image: https://www.hackthebox.com/storage/avatars/10c8da0b46f53c882da946668dcdab95.png
headerImage: true
writeups: true
hidden: true # don't count this post in blog pagination
description: "An easy retired HackTheBox machine."
category: project
author: johndoe
externalLink: false
star: false
---

# Overview

Academy is the box HTB used, in classic HTB style, to soft launch the HTB Academy platform. It featured a clone of the Academy website with a web application vulnerability like a real-world web application penetration test, followed by a vulnerable version of the PHP Laravel framework in use by the platform. It required common Linux enumeration tasks to perform lateral movement and privilege escalation.

---

# Namp
```bash
$ nmap -A -T4 10.10.10.215    
Starting Nmap 7.91 ( https://nmap.org ) at 2023-07-25 16:42 +01
Nmap scan report for 10.10.10.215
Host is up (0.10s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Hack The Box Academy
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=7/25%Time=64BFF948%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOptions
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000
SF:")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Gobuster

![!\[\[Pasted image 20230726100024.png\]\]](../../../assets/images/HTBPics/20230726100024.png)

Found the admin.php page!

I tried to register as a normal user (roleid=0) but I cannot login into the admin.php page so I changed the `roleid` to 1 and voilà :

![!\[\[Pasted image 20230726095007.png\]\]](../../../assets/images/HTBPics/20230726095007.png)

<p>After login in the admin.php page I was redirected to admin-page.php where I found a subdomain:</p>

`dev-staging-01.academy.htb`

![!\[\[Pasted image 20230726094713.png\]\]](../../../assets/images/HTBPics/20230726094713.png)

<p>Here I found the laravel php framework running on the subdomaine which is vulnerable :</p>

![!\[\[Pasted image 20230726095516.png\]\]](../../../assets/images/HTBPics/20230726095516.png)

Exploit : [https://github.com/aljavier/exploit_laravel_cve-2018-15133](https://github.com/aljavier/exploit_laravel_cve-2018-15133)

![!\[\[Pasted image 20230726095959.png\]\]](../../../assets/images/HTBPics/20230726095959.png)

Exploit worked!
So now I'll try to get a reverse shell :

![!\[\[Pasted image 20230726100655.png\]\]](../../../assets/images/HTBPics/20230726100655.png)

![!\[\[Pasted image 20230726100643.png\]\]](../../../assets/images/HTBPics/20230726100643.png)

Now I'm in!

## www-data -> cry0l1t3

in /var/www/html/academy/.env I found the **cry0l1t3** password : **mySup3rP4s5w0rd!!**

![!\[\[Pasted image 20230726101716.png\]\]](../../../assets/images/HTBPics/20230726101716.png)

<p>Then I logged in to ssh to have a stable shell.</p>

## User flag

<p>cry0l1t3@academy:~$ cat user.txt</p>
658bbf894e65319a70d5b12cc82031b4

## cry0l1t3 -> mrb3n

<p>As we can see *cry0l1t3* is a memeber of the *adm group*.</p>

> The Adm group is used in Linux for system monitoring tasks. Members of this group can read many log files in /var/log

![!\[\[Pasted image 20230726110720.png\]\]](../../../assets/images/HTBPics/20230726110720.png)

After a lot of tries, I decided to grep -ir "data" in the /log/var/audit directory then I found the *mrb3n* HEX encoded password, I decoded it using **CyberChef** :

<p></p>

**mrb3n : mrb3n_Ac@d3my!**

![!\[\[Pasted image 20230726110847.png\]\]](../../../assets/images/HTBPics/20230726110847.png)

Now I'm in :

![!\[\[Pasted image 20230726111121.png\]\]](../../../assets/images/HTBPics/20230726111121.png)

**sudo -l** showed me that *mrb3n* can execute /usr/bin/composer as root.

I found how to exploit this on : [https://gtfobins.github.io/gtfobins/composer](https://gtfobins.github.io/gtfobins/composer)

![!\[\[Pasted image 20230726111349.png\]\]](../../../assets/images/HTBPics/20230726111349.png)

Voilà I'm root!!

## Root flag

<p>cat /root/root.txt</p>
f3a09f54c7871686e24afee50e4dfa3b


<br/>

# MACHINE PWNED!

<br/>

That was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>