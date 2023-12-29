---
title: "HackTheBox | OpenAdmin"
layout: post
date: 2023-08-09 19:00
tag: 
- HackTheBox
- Pentesting
- OpenAdmin
- Linux
- Easy
- OpenNetAdmin
image: https://www.hackthebox.com/storage/avatars/5b00db157dbbd7099ff6c0ef10f910ea.png
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

OpenAdmin is an easy retired linux machine that features an outdated OpenNetAdmin CMS which is exploited to gain a foothold, and enumeration reveals database credentials. These credentials are reused to move laterally to a low privileged user. This user is found to have access to a restricted internal application. Examination of this application reveals credentials that are used to move laterally to a second user. A sudo misconfiguration is then exploited to gain a root shell.

---

# Nmap

```bash
nmap -A -T4 10.10.10.171  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-15 10:32 EDT
Nmap scan report for 10.10.10.171
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

Firstly, I checked the web page at port 80, I found the Apache2 default page :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015160143.png>)

So I used **Gobuster** to fuzz for directories :

# Gobuster

```bash
gobuster dir -u http://10.10.10.171 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/index.html           (Status: 200) [Size: 10918]
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

The */artwork* endpoint doesn't contains any valuable information :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015160212.png>)

But the */music* endpoint does, when I click on the login button, they redirect me to the */ona* endpoint :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015161036.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015160918.png>)

It's an OpenNetAdmin page, which has the 18.1.1 version, I googled if it's vulnerable and yes it is vulnerable to RCE, I found and exploit for that :

[https://github.com/amriunix/ona-rce](https://github.com/amriunix/ona-rce)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015161133.png>)

I'm in as www-data user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015161204.png>)

I found a config db file that contains a password, I said maybe it would be reused for another user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015162917.png>)

And that was the case, I can login in ssh as jimmy with this password :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015162854.png>)

But I cannot read the user flag yet, because it's located on Joanna's home directory.
I found another vhost running which was :  `internal.openadmin.htb`

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015163433.png>)

# Jimmy -> Joanna

The index.php contains a username which is jimmy and its sha512 hashed password that I will use maybe to access that portal in the vhost:

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015163407.png>)

We can see in main.php that when we access the vhost successfully, we will get the Joanna's private key :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164553.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015163349.png>)

When I checked the open connections using **netstat**, I found a suspicious service running under port 52846 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164324.png>)

So I did ssh port forwarding to access that service :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164310.png>)

And here I was prompted for jimmy's password we decoded before :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164229.png>)

And here is Joanna's private key. Now I can login into ssh as Joanna user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164243.png>)

The file was protected with a password, which I found easily using **JohnTheRipper** :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164457.png>)

Now I'm in as Joanna this time :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015164720.png>)

# PE

First thing I checked was what can Joanna do as root, and I found that she can execute */bin/nano* command on */opt/priv* as root :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015165116.png>)

We can refer to **GTFObins** to exploit that easily :

[https://gtfobins.github.io/gtfobins/nano](https://gtfobins.github.io/gtfobins/nano)

And Boom I'm root :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015165014.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231015165315.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>