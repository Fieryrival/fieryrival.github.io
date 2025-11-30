---
title: "Beyond the Blog: Exploiting WordPress CVEs on HTB 'MetaTwo'"
seo_title: "Hack The Box 'MetaTwo' Write-up: A Step-by-Step Guide"
date: 2025-11-30
layout: single
hideToc: false
tags: ["linux", "easy", "hackthebox", "web", "wordpress", "cve", "sqli", "xxe", "lfi", "passpie"]
summary: "Write-up for 'MetaTwo', a box that involves exploiting WordPress CVEs with multiple vectors (SQLi, XXE, LFI) for foothold, and then leveraging passpie for root privilege escalation."
---

# MetaTwo

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled.png)

It was an easy linux box created by [Nauten](https://app.hackthebox.com/users/27582) with foothold based on two CVE one being unauthenicated sqli which led to leaking credentials then using the credentials authenticated xxe with wordpress verison 5.6.2.

We were able to log into user and then privesc included gpg2john passphrase for getting root credentials from passpie.

## Nmap

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPp9LmBKMOuXu2ZOpw8JorL5ah0sU0kIBXvJB8LX26rpbOhw+1MPdhx6ptZzXwQ8wkQc88xu5h+oB8NGkeHLYhvRqtZmvkTpOsyJiMm+0Udbg+IJCENPiKGSC5J+0tt4QPj92xtTe/f7WV4hbBLDQust46D1xVJVOCNfaloIC40BtWoMWIoEFWnk7U3kwXcM5336LuUnhm69XApDB4y/dt5CgXFoWlDQi45WLLQGbanCNAlT9XwyPnpIyqQdF7mRJ5yRXUOXGeGmoO9+JALVQIEJ/7Ljxts6QuV633wFefpxnmvTu7XX9W8vxUcmInIEIQCmunR5YH4ZgWRclT+6rzwRQw1DH1z/ZYui5Bjn82neoJunhweTJXQcotBp8glpvq3X/rQgZASSyYrOJghBlNVZDqPzp4vBC78gn6TyZyuJXhDxw+lHxF82IMT2fatp240InLVvoWrTWlXlEyPiHraKC0okOVtul6T0VRxsuT+QsyU7pdNFkn2wDVvC25AW8=
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB1ZmNogWBUF8MwkNsezebQ+0/yPq7RX3/j9s4Qh8jbGlmvAcN0Z/aIBrzbEuTRf3/cHehtaNf9qrF2ehQAeM94=
|   256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP4kxBr9kumAjfplon8fXJpuqhdMJy2rpd3FM7+mGw2
80/tcp open  http    syn-ack nginx 1.18.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: MetaPress &#8211; Official company site
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: WordPress 5.6.2
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Website at TCP 80

We add the entry `metapress.htb` to the hosts file to access the website. Greeted with a WordPress powered website with a message to be launched soon. Looking at the source code we got to know that the WordPress version was 5.6.2 which is vulnerable to XML external entities where an authenticated user can upload a malicious wav file that could lead to arbitrary file disclosure and server-side request forgery.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%201.png)

Moving on with directory brute-forcing we found the events directory has a feature for booking appointments. Looking at the source code we got to know that it was version 1.0.10 which was vulnerable to unauthenticated SQL injection.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%202.png)

### Unauthenticated SQLi

With some googling stumbled upon a website with POC of the exploit and tried the basic payload there and got confirmation of the SQL.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%203.png)

We edited the existing payload to reveal table_names and column names. We know that the user login credentials are stored in the users table which was table wp_users with columns user_login and user_pass.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%204.png)

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%205.png)

We were able to extract two usernames (admin, manager) and respective hashes. 

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%206.png)

Tried cracking the hashes with John the Ripper and we were lucky to get a password for the manager user account.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%207.png)

### XXE to LFI

Now we can look ahead to the XXE vulnerability of the WordPress website.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%208.png)

So we confirmed the vulnerability and now moving on to looking for interesting files. First, we look at the nginx config files which are by default at `/etc/nginx/sites-enabled/default` . We were able to successfully locate the root directory of the blog website. Now we can take a look at the config files. Here we could also use `../wp-config.php` if we didn't know about the absolute location of the website.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%209.png)

Since the root directory is `/var/www/metapress.htb/blog` we know that wp-config.php would also be in the same directory. So we edit the `evil.dtd` to point to `/var/www/metapress.htb/blog/wp-config.php`

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2010.png)

We were able to exfiltrate the credentials of FTP and DB. Since the FTP port was open in our initial recon we can look into the FTP directory for files.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2011.png)

We found directories blogs and mailer. Looking at the mailer we found a `send_email.php` file having credentials for using jnelson.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2012.png)

### Privilege Escalation

We were able to ssh into jnelson with the credentials and move on to privesc.

The home directory contained a directory `.passpie` which was our privesc vector. On running passpie command we could see there were ssh passwords for root and jnelson but we needed a passphrase to get them in plaintext. Inside the `.passpie` directory, there were also the public and private keys used to encrypt the passwords so we copied the file to our own machine.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2013.png)

I tried to extract the hash for John the ripper but it didn't work and we needed to separate the two keys.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2014.png)

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2015.png)

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2016.png)

The passphrase was “blink182”. With this, we could dump the passwords in the current working directory and get root.

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2017.png)

![Untitled](MetaTwo%20559fd9799b5a4b6cb2e2b2f90989e87b/Untitled%2018.png)

## References

[https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357)

[https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/)