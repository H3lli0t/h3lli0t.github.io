---
title: "TwoMillion HackTheBox"
layout: post
date: 2023-07-29 18:00
tag: 
- HackTheBox
- Linux
- Pentesting
- Machines
- TwoMillion
- API
- Easy
image: https://www.hackthebox.com/storage/avatars/d7bc2758fb7589dfa046bee9ce4d75cb.png
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

TwoMillion is an easy linux box that features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and a known CVE can be used to gain a root shell.

---

# Nmap

```bash
$ nmap -A -T4 10.10.11.221
Starting Nmap 7.91 ( https://nmap.org ) at 2023-07-28 15:48 +01
Warning: 10.10.11.221 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.221
Host is up (0.22s latency).
Not shown: 996 closed ports
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open     http       nginx
|_http-title: Did not follow redirect to http://2million.htb/
5432/tcp  filtered postgresql
61900/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


I found myself in front of a web page I run burp and see the endpoints, I found there is a js code in */js/inviteapi.js*

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728163447.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728164254.png>)

I used js beautify to see the code cleary :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728160208.png>)

I sent a post request to the URL mentioned above :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728160148.png>)

I decoded the string in data using ROT13 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728160301.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728160421.png>)

I base64 decoded the Invite code : *9M7OE-DNK25-LWD80-PO1OU*

Then I registered using the invite code in */invite* with : test@test.com : test
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728160626.png>)

Then I started looking for an endpoint where I can find something interesting in, I found */api/v1* that gives some hints :
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728165143.png>)

I updated the *is_admin* in */api/v1/admin/settings/update* from 0 to 1 to give admin role to my user :
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728170624.png>)

Then I verified it with a GET request to */api/v1/admin/auth* :
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728170724.png>)

I went then to */api/v1/admin/vpn/generate* and I found that this api is vulnerable to Code Injection, I tried first to inject the payload "admin; cat /etc/passwd" but didn't work till I added a space after the command :
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728173054.png>)

Et voilà I am in!
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728173452.png>)

# www-data -> admin

<p>Using linepeas I was abled to find a hidden file in /var/www/html which contains admin creds:</p>

**admin : SuperDuperPass123**
<br/>
![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728174615.png>)

So I logged in as admin using ssh.

# User flag

admin@2million:~$ cat user.txt 
f3578e9d075a8dbed6a5e34637fd3f6d

# PE

I run linepeas but it was a dead end. Then I remembered that when I first logged in I see You have an email message, so I deciced to check the content of /var/mail :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728200126.png>)

Output of */var/mail/admin* :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728200330.png>)

He is talking about the OverlayFS vulnerability.

>The overlay file system (OverlayFS) allows a user to merge several mount points into a unified file system.

I found a POC for this CVE : [https://github.com/xkaneiki/CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386)

>CVE-2023-0386 lies in the fact that when the kernel copied a file from the overlay file system to the "upper" directory, it did not check if the user/group owning this file was mapped in the current user namespace. This allows an unprivileged user to smuggle an SUID binary from a "lower" directory to the "upper" directory, by using OverlayFS as an intermediary.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728203104.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230728203043.png>)

# Root flag

root@2million:~# cat /root/root.txt 
e64826a6d8e20d00ae7acfdb04c56742

<br/>

# MACHINE PWNED!

<br/>

That was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>