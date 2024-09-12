
## Information 

Release Date: 2023/8/12
Fix Date: 2023/8/?
Upload Note Date: 2023/9/23

![](./IMG/38.png)

## Reconnaissance

### nmap 

```
nmap -sC -sV -oN keeper_light 10.10.11.227
```

![](./IMG/0.png)
### Web Service

- Access target site, it will guide us to move to tickets.keeper.htb

![](./IMG/1.png)
- Add the domain to /etc/hosts
```
10.10.11.227 tickets.keeper.htb keeper.htb
```
- Access tickets site, it's a login page 

![](./IMG/2.png)
- I can find some software information - RT 4.4.4
- According to this information, I search it and find it has default credential for login
```
root / password 
```

![](./IMG/3.png)
- Login by this default credential 

![](./IMG/4.png)
- Enumerate ticket site
- User Management

![](./IMG/7.png)
- Check user Inorgaard detail

![](./IMG/5.png)
- find another user credential in user management panel 
```
Inorgaard / Welcome2023!
```
![](./IMG/6.png)

## Exploit 

- Using SSH to login with the credential

![](./IMG/8.png)
- Check user 
```
id
```
![](./IMG/9.png)
- Check /etc/passwd
```
cat /etc/passwd
```
![](./IMG/10.png)
- Check user directory 
- Get user flag

![](./IMG/12.png)
- Besides user flag, there is another interesting zip file 

![](./IMG/13.png)

## Privilege Escalation 

- Download the zip file to my local and unzip it
- There are 2 files, a dmp file and a kdbx file
- With the file extension, I know that is a keePass file which will record user's password.
- Besides the kdbx file, there is another file with extension .dmp

![](./IMG/11.png)
- Using these 2 clue, I do some research, it's easy to find a latest cve on keepass - CVE-2023-32784

### CVE-2023-32784 

```
In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.
```

![](./IMG/14.png)
- With the search result, this [github PoC](https://github.com/vdohney/keepass-password-dumper) is most recommend or mentioned.

![](./IMG/15.png)
- But I read the content, it suggest to execute in Windows Powershell. 

![](./IMG/16.png)
- So I keep searching the PoC for linux environment.
	- One is wrote by C - [(GITHUB)PoC](https://github.com/CTM1/CVE-2023-32784-keepass-linux)
	- Second one is wrote by python - [(GITHUB)PoC](https://github.com/z-jxy/keepass_dump)
	- Third one also is wrote by python, and I use this one to get the master password - [(GITHUB)PoC](https://github.com/4m4Sec/CVE-2023-32784)
![](./IMG/17.png)
- Execute the poc, I got some possibilities
```
python poc.py -d ../KeePassDumpFull.dmp
```

![](./IMG/22.png)
- With the description in github, I think the first character won't show by executing the payload directly
```
As a reminder, the first character cannot be found in the dump, and for the second the script will only give you a few possibilities, in any case we recommend you to run the bruteforce on 2 chars with the script below
```
![](./IMG/18.png)
### BruteForce Script From [GITHUB](https://github.com/4m4Sec/CVE-2023-32784)
```
#!/bin/sh
# Usage: ./keepass-pwn.sh Database.kdbx wordlist.txt (wordlist with 2 char)
while read i
do
    echo "Using password: \"$i\""
    echo "$i" | kpcli --kdb=$1 && exit 0
done < $2
```
- But I didn't use the script to bruteforce password.
- Instead, I just think all the possibility results are similar to the user name(Inorgaard). 
![](./IMG/19.png)
- So, I google the user name (Inorgaard), the result shows a Danish soccer player's name - Norgaard.

![](./IMG/20.png)
- It's a little different, but I think the word is definitely a Danish word.
- So, I think the master password must a Danish word, too. 
- I search 'med flode' by google.
- yes I think the master password: 
```
Rødgrød med fløde
```

![](./IMG/21.png)
- So I open kdbx file with above master password

![](./IMG/23.png)
- After pass auth, I start to enumerate this kdbx.

![](./IMG/24.png)
- I found  some credential for keeper.htb in passcodes/Network/
```
cd passcodes/Network
ls 
```

![](./IMG/26.png)
- Show credentail
```
show 0
```
- The credential as follow 
```
root / F4><3K0nd!
```
![](./IMG/25.png)
- with this credential, I tried to login by ssh, but failed.

![](./IMG/27.png)
- I read more detail about the credential in keepass.
- Here is a Notes messsage: 
```
PuTTY-User-KeyFile-3: ssh-rs
```
- So I think it is a passcode for Putty User key.
- I think I need to use user key and passcode to login, so I copy the key value to a file 
```
echo <key value> >> putty2
```

![](./IMG/28.png)
- Then login again, but it still failed.
- The error message is 'permission denied and bad permission for key'

![](./IMG/29.png)
- So I tried to escalate the permission for this key
```
chmod 400 putty2
```

![](./IMG/30.png)
- Login again and failed again.

![](./IMG/31.png)
- I start to research how to use putty user key to login ssh service, I found [this one](https://www.liquidweb.com/kb/putty-ssh-keys/)
- The putty user key should be generated by software: puttygen.exe at first, and the private key will be .ppk

![](./IMG/32.png)
- I think the key file I found also is a ppk.
- And I also noticed that it's not possible to use openssh login with ppk directly.
- With this [discussion](https://askubuntu.com/questions/818929/login-ssh-with-ppk-file-on-ubuntu-terminal), following the step to generate .pem file for connecting by openssh service 

![](./IMG/33.png)
- Install putty-tools
```
sudo apt-get install putty-tools
```

![](./IMG/34.png)
- Generating putty format's key pem file
```
puttygen putty -O private-openssh -o key.pem
```

![](./IMG/37.png)
- SSH login with key pem 
```
ssh -i key.pem root@10.11.227
```

![](./IMG/35.png)
- Get root flag

![](./IMG/36.png)

## Reference 


### Writeup 

- [HTB: Keeper](https://0xnirvana.medium.com/htb-keeper-a6c5798fc681)
- [HackTheBox Write-Up: Keeper - Easy](https://maddevs.io/writeups/hackthebox-keeper/)
- [HTP-Keeper](https://blog.csdn.net/qq_37370714/article/details/132286578)
- [Keeper HTB Walkthrough](https://techyrick.com/keeper-htb-walkthrough/)

### Other related information 

- [Google Search - Inorgaard](https://www.google.com/search?q=Inorgaard&rlz=1C5CHFA_enTW1055TW1055&oq=Inorgaard+&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIJCAEQABgNGIAEMgkIAhAAGA0YgAQyCQgDEAAYDRiABDIJCAQQLhgNGIAEMgkIBRAAGA0YgAQyCQgGEAAYDRiABDIICAcQABgNGB4yCAgIEAAYDRgeMggICRAAGA0YHtIBBzcxM2owajeoAgCwAgA&sourceid=chrome&ie=UTF-8&bshm=rime/1)
- [Wiki - Christian Nørgaard](https://en.wikipedia.org/wiki/Christian_N%C3%B8rgaard)
- [Wiki - rødgrød med fløde](https://en.wiktionary.org/wiki/r%C3%B8dgr%C3%B8d_med_fl%C3%B8de)
- [DANISH RED BERRY PUDDING (RØDGRØD MED FLØDE)](https://nordicfoodliving.com/danish-red-berry-pudding-rodgrod-med-flode/)

### CVE-2023-32784

- [(NVD)CVE-2023-32784 Detail](https://nvd.nist.gov/vuln/detail/cve-2023-32784)
- [(GITHUB)KeePass 2.X Master Password Dumper](https://github.com/vdohney/keepass-password-dumper)
- [(GITHUB)# keepass-dump-masterkey](https://github.com/4m4Sec/CVE-2023-32784)
- [EASY: Dumping the KeePass Master Password - CVE-2023-32784](https://www.youtube.com/watch?v=EXgd4AV-VPQ)
- [KeePass exploit helps retrieve cleartext master password, fix coming soon](https://www.bleepingcomputer.com/news/security/keepass-exploit-helps-retrieve-cleartext-master-password-fix-coming-soon/)
- [KeePass CVE-2023-32784: Detection of Processes Memory Dump](https://sysdig.com/blog/keepass-cve-2023-32784-detection/)

### KeePass Related 

- [How to Hack KeePass Passwords using Hashcat](https://rubydevices.com.au/blog/how-to-hack-keepass)
- [How to crack a KeePass Database file](https://www.thedutchhacker.com/how-to-crack-a-keepass-database-file/)
- [How to Install kpcli on Kali Linux](https://installati.one/install-kpcli-kalilinux/)

### RT Related 

- [Forgot admin password of RT](https://forum.bestpractical.com/t/forgot-admin-password-of-rt/33451)
- [RT: Request Tracker - RT 4.4.4 Release Notes](https://docs.bestpractical.com/release-notes/rt/4.4.4)

### Putty User Key v.s. OpenSSH

- [Login SSH with .ppk file on Ubuntu Terminal](https://askubuntu.com/questions/818929/login-ssh-with-ppk-file-on-ubuntu-terminal)
- [Generating and Using SSH Keys with PuTTY](https://www.liquidweb.com/kb/putty-ssh-keys/)

### Not Related Information 

- [Request Tracker - 'ShowPending' SQL Injection](https://www.exploit-db.com/exploits/38459)

###### tags: `HackTheBox` `RT 4.4.4` `KeePass` `CVE-2023-32784` `Putty Private Key` `PPK for OpenSSH` `puttyGen` 
