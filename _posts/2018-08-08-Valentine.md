---
layout: post
title: "HackTheBox: Valentine"
description: "hackthebox valentine walkthrough"
thumb_image: "TODO"
tags: [web, ctf, overthewire]
permalink: /posts/Valentine
---

## Enumeration

#### Port scans


Unless there is some form of rate limiting I like to initially scan all ports on CTF type boxes. It's not uncommon to find some service running on a random high number port and if we can recognise that early we can save ourselves time later.

We start off with a SYN scan (-sS), of all ports (-p-), there's no DNS in this environment so let's turn off name resolution (-n), and save output in all formats with the filename "allports" (-oA allports):

```
root@kali: nmap -sS -p- -n -oA allports -e tun0 -vv 10.10.10.79

# Nmap 7.70 scan initiated Wed Jul 18 03:46:04 2018 as: nmap -sS -p- -n -oA allports -e tun0 -vv 10.10.10.79
Nmap scan report for 10.10.10.79
Host is up, received reset ttl 63 (0.28s latency).
Scanned at 2018-07-18 03:46:04 EDT for 338s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Jul 18 03:51:42 2018 -- 1 IP address (1 host up) scanned in 338.06 seconds
```




We have three open ports, let's try and enumerate some version information with nmap. So we look at ports 22,80 and 443 (-p 22,80,443) using service detection (-sV), saving all outputs with the filename "scripts" (-oA scripts) and with name resolution still off (-n):

```
# Nmap 7.70 scan initiated Wed Jul 18 04:01:38 2018 as: nmap -sV -p22,80,443 -n -oA scripts -e tun0 -vv 10.10.10.79
Nmap scan report for 10.10.10.79
Host is up, received echo-reply ttl 63 (0.27s latency).
Scanned at 2018-07-18 04:01:38 EDT for 17s

PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.2.22 ((Ubuntu))
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.2.22 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
*Something fun to note at this point is that we can already make a good guess at what operating system we're looking at. Can you figure it out? Answer at the bottom.*

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 18 04:01:55 2018 -- 1 IP address (1 host up) scanned in 17.36 seconds
```
#### Web

Web servers are always something we want to have a look at. Pointing our browser to 10.10.10.79 we're served a landing page with this image:

![webfront](/img/valentine/webfront.png)

A bleeding heart... maybe this box has something to do with heartbleed, we'll note that for later.

Let's quickly enumerate with gobuster and see if there's anything more we should be looking at on the web ports. We'll use a default kali wordlist called big.txt (-w /usr/share/wordlists/dirb/big.txt), with 50 concurrent threads (-t 50) at the server (-u 10.10.10.79):

```
root@kali: gobuster -w /usr/share/wordlists/dirb/big.txt -u 10.10.10.79 -t 50 -f

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.79/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirb/big.txt
[+] Status codes : 200,204,301,302,307
[+] Add Slash    : true
=====================================================
/decode/ (Status: 200)
/dev/ (Status: 200)
/encode/ (Status: 200)
/index/ (Status: 200)
=====================================================
```

Checking the hits in our browser we see /decode and /encode appear to be some simple application, it looks like they're encoding or decoding input to base64. Navigating to /dev/ we see it's a directory containing notes.txt, and a file called "hype_key":

![hype key](/img/valentine/hype_key.png)

Hype_key looks to be encoded in hexadecimal, all the characters are in the range 0-F. To confirm we can go to the Decoder tab in Burp Suite and enter the data before selecting "ASCII Hex" in the "Decode as" dropdown:

![decoder](/img/valentine/decoder.png)

That's neat, we have an RSA key that requires a password. We also have whitespace every second character in our output that needs to be cleaned up. To get a usable key file we can echo the raw data, pipe it into [tr](https://en.wikipedia.org/wiki/Tr_(Unix)) to remove the whitespace, then pipe into the xxd to convert from hex to ascii and finally redirect the ouput into a file:

```
echo "2d 2d 2d..." | tr -d ' ' | xxd -r -p > hype.key
```

So we have a key and can make a guess at a username (hype seems like a good first try). Our key is password protected. If we find a password maybe we'll be able to use this key to SSH into the box... let's keep poking around.

#### SSL

Earlier we saw a hint that the server might be vulnerable to heartbleed. We can use sslscan to get a whole load of information about the SSL server on port 443:

![sslscan](/img/valentine/sslscan.png)

Looks like this server is vulnerable.

## Exploitation
#### Heartbleed


Googling for "heartbleed poc" we come across https://github.com/sensepost/heartbleed-poc. Running this proof of concept we see it's dumping memory, but we don't see anything in that memory that is useful for us:

![heartbleed](/img/valentine/uselessheartbleed.png)

At this point if we [RTFM](https://en.wikipedia.org/wiki/RTFM) we'd notice a -n option in the PoC to take multiple heartbeats, hopefully returning multiple slices of memory. An uglier way of achieving this is to run the script multiple times in a bash loop and have each output appended to a file:

```
for i in {1..10}; do python heartbleed-poc.py 10.10.10.79 >> heartbleed.output; done
```

Looking at that output we see an interesting string that looks like a parameter being passed to the server.


![interesting heartbleed](/img/valentine/interestingheartbeat.png)

```
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==
```

When we see a string ending in two equals signs it's often diagnostic of having been base64 encoded (which is further hinted at by the base64 encoder/decoder pages on the website). We can check that from the command line:

![there's our password](/img/valentine/b64.png)

Looks like we have a password to try!

#### SSH

After changing the permissions of our key we can successfully login via SSH and cat the user flag (I'll leave this step to the reader).

![SSH in](/img/valentine/ssh.png)

## Privelege Escalation
Having SSH access allows us to upload enumeration scripts using SCP. One such script is  [LinEnum.sh](https://github.com/rebootuser/LinEnum). We SCP it to the server's /tmp directory:

```
scp -i hype.key LinEnum.sh 10.10.10.79:/tmp/
```

after chmodding the file to be executable and running it on the server we get a heap of information about the system. At the end of the output we see there's a .bash_history file with some interesting content:

![LinEnum output](/img/valentine/linenum.png)

Looks like someone has created a tmux socket at /.devs/dev_sess. Let's check out the permissions for that socket:

![devss](/img/valentine/devss.png)

So it's owned by the root user, but the hype group has read/write access. We can connect to the socket with
```
tmux -S /.devs/dev_sess
```
Let's connect and see what user we are:

![root shell](/img/valentine/rootshell.png)

And we're root! Job done. From here we can cat the root flag and call it a day.




## Notes
We can have a good guess at what family of operating system is being used after the very first nmap scan. The TTL of a SYN-ACK packet is different between systems. In our case we had a ttl of 63, \*NIX systems set a TTL of 64, and the packet has crossed one network segment, so we can already make a good guess that we're looking at a \*NIX machine. For other TTL values see  [http://www.kellyodonnell.com/content/determining-os-type-ping](http://www.kellyodonnell.com/content/determining-os-type-ping)
