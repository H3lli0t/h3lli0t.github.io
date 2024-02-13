---
title: "HackTheBox | Keeper"
layout: post
date: 2024-02-10 12:00
tag: 
- HackTheBox
- Pentesting
- Keeper
- Linux
- Easy
- Keepass
- Putty
image: https://labs.hackthebox.com/storage/avatars/b56a5742b99e2568fa167765b1323370.png
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

Keeper is an easy Linux HackTheBox machine that features a support ticketing system that uses default credentials. Enumerating the service, we are able to see clear text credentials that lead to SSH access. Then we gain access to a KeePass database dump file, which we can leverage to retrieve the master password. With access to the Keepass database, we can access the root SSH keys, which are used to gain a privileged shell on the host.

---

# Nmap

```bash
nmap -A -T4 10.129.203.232
Starting Nmap 7.91 ( https://nmap.org ) at 2023-08-12 20:04 +01
Nmap scan report for 10.129.203.232
Host is up (0.074s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20230812200637.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813023910.png>)

I logged in using default credentials :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230812213907.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20230812213931.png>)

I'm in :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813002008.png>)

I found an interesting zip file which I transfered to my local machine :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230812222425.png>)

I read the mail which gave me a hint that the file is a crash dump of keepass :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813002428.png>)

The zip file contains two files, the KeePass dump file and the KeePass password database :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813004647.png>)

[https://github.com/vdohney/keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper)
[https://www.linkedin.com/pulse/steal-keepass-2x-254-master-password-chance-johnson](https://www.linkedin.com/pulse/steal-keepass-2x-254-master-password-chance-johnson)

Following the POC above :

```bash
dotnet run KeePassDumpFull.dmp
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813004418.png>)

I used hashcat but gave me nothing :

```bash
hashcat.exe -m 13400 hash_only.txt -a 3 -1 ?l?l?l "M?ldgr?ld med fl?lde" -O
```

Then I tried to google the phrase as it is maybe it refers to something famous, and it was the case!

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813012220.png>)

```bash
keepass2 passcodes.kdbx
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813024659.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813011922.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813011907.png>)

#### Method 1

I used PuttyGen to generate the private key file (.ppk) to be able to login with putty :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813023453.png>)

I loaded the private key :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813025615.png>)

BOOM I'm in as root user :

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813023212.png>)

#### Method 2

We can convert PuTTY private key we have to OpenSSH format and login then via ssh :

```bash
puttygen id_rsa.ppk -O private-openssh -o id_rsa
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20230813024149.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>