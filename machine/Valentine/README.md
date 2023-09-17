
## Reconnaissance 

### nmap 
```
nmap -sC -sV -oA valentine 10.129.228.141
```

![[Image/[IMG]Valentine/0.png]]
### WebSite 

- HTTP
```
http://10.129.228.141
```

![[Image/[IMG]Valentine/1.png]]
- HTTPS
```
https://10.129.228.141
```

![[Image/[IMG]Valentine/2.png]]
### Gobuster 

- HTTP
```
gobuster -u http://10.129.228.141 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![[Image/[IMG]Valentine/3.png]]
- HTTPS
```
gobuster -u http://10.129.228.141 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-tls-validation
```

### Enumerate to path

```
/dev 
```

![[Image/[IMG]Valentine/4.png]]
```
/dev/notes.txt
```

![[Image/[IMG]Valentine/5.png]]
- ``` /dev/hype_key ```

![[Image/[IMG]Valentine/6.png]]
- Copy the content of hype_key
- Paste it to Decoder function in BurpSuite, and decode it to ASCII-text
- Got the RSA private key (The format looks like strange in Decoder.)

![[Image/[IMG]Valentine/7.png]]
- Translate it in online tool

![[Image/[IMG]Valentine/8.png]]
- Store the private key to file by terminal
1. Downloading hex file from website 
```
curl http://10.129.228.143/dev/hype_key_hex 
```
![[Image/[IMG]Valentine/9.png]]
2. Convert it by following command 
```
cat hype_key_hex | xxd -r -p > hype_key
```
![[Image/[IMG]Valentine/10.png]]

![[Image/[IMG]Valentine/11.png]]
- Try this private key to login --> failed 
- It will ask to password, it's different from I thought at first.

![[Image/[IMG]Valentine/12.png]]
- Check the private key detaily, it looks like a little different.

![[Image/[IMG]Valentine/13.png]]
- This key start from the following: 
```
Proc- Type:4, ENCRYPTED
DEK-Info:AES-128-CBC, ....
```

### Encode and Decode Page
- The other page is encode and decode 
- /encode.php 

![[Image/[IMG]Valentine/14.png]]
- /decode.php

![[Image/[IMG]Valentine/15.png]]
- Try encode function page 
- Input value for encoding: eeee
- The output encode result: ``` ZWVlZQ== ```

![[Image/[IMG]Valentine/16.png]]
- Try Decode function page 
- Input value for decoding: ``` ZWVlZQ== ```
- Output decode result:  ```eeee```

![[Image/[IMG]Valentine/17.png]]
- After those test, I think the encode and decode method is base64. 
- But the hype_key is converted by ASCII hex.

### /omg
- Access to ```/omg ```
- It's a picture which display in home page 

![[Image/[IMG]Valentine/18.png]]
- Download it and analysis it by binwalk and exiftool
- But nothing special 
```
exiftool omg.jpeg
binwalk -Me omg.jpeg
```

![[Image/[IMG]Valentine/19.png]]

> With above information, I know this page has a string encode and decode function, and it also has a file directory which content a private key with hex format.
> Try the hype as username, but it still need password to login.
> I still don't know the password.

### Step from ippsec

>Search the information from 1st nmap result,
>I can know the SSH version and httpd version
>Search Ubuntu 2.2.22 apache, and I can know what kind of Ubuntu version using --> precise
>So I know the precise is very old version which release in 2014 and eol now.
>So using vuln scan for old version software which is eol usually very helpful

### Using nmap to scan the vulnerability 

```
nmap -sV -v --script vuln -oA valentine1 10.129.228.141
```

![[Image/[IMG]Valentine/20.png]]
- Result for ssh service 

![[Image/[IMG]Valentine/21.png]]
- Result for HTTP service 

![[Image/[IMG]Valentine/22.png]]

![[Image/[IMG]Valentine/23.png]]
- Result for HTTPS service 
- ssl-ccs-injection
- cve-2014-0224

![[Image/[IMG]Valentine/24.png]]
- ssl heartbleed
- cve-2014-0160

![[Image/[IMG]Valentine/25.png]]
- ssl poodle
- cve-2014-3566

![[Image/[IMG]Valentine/26.png]]
- sslv2-drown

![[Image/[IMG]Valentine/27.png]]
- Rest of CVE releated to sslv2

![[Image/[IMG]Valentine/28.png]]
## Exploitation

### SSL Heartbleed Attack

- According to the [research](https://devco.re/blog/2014/04/09/openssl-heartbleed-CVE-2014-0160/)
> 這個漏洞能讓攻擊者從伺服器記憶體中讀取 64 KB 的資料，利用傳送 heartbeat 的封包給伺服器，在封包中控制變數導致 memcpy 函數複製錯誤的記憶體資料，因而擷取記憶體中可能存在的機敏資料。記憶體中最嚴重可能包含 ssl private key、session cookie、使用者密碼等，因此可能因為這樣的漏洞導致伺服器遭到入侵或取得使用者帳號。

- Find the exploit in metasploit
- Run the exploit.

![[Image/[IMG]Valentine/29.png]]
- Check the result directory 

![[Image/[IMG]Valentine/30.png]]
- Check the content

![[Image/[IMG]Valentine/31.png]]
- Check the base64 encode word and decode it
- Got a string: ``` heartbleedbelievethehtpe ```
- It might be a password for ssh login 

![[Image/[IMG]Valentine/32.png]]

### SSH login 

- Try to use this RSA private key and password. --> Still failed due to improper permission for "hype_key" --> "Load key 'hype_key': bad_permission"
```
ssh -i hype_key hype@10.129.228.143
```

![[Image/[IMG]Valentine/33.png]]
- Change the key permission
```
chmod 400 hype_key
```
- Login again with password

![[Image/[IMG]Valentine/34.png]]
#### Second method 
- Using openssl to regenerate another key to login. 
- Generate a new ssh RSA key by private key from ```/dev/hype_key ``` and password 

``` openssl rsa -in hype_key -out new.key```

![[Image/[IMG]Valentine/35.png]]
- SSH login
```
ssh -i new.key hype@10.129.228.143
```

![[Image/[IMG]Valentine/36.png]]
- Get user flag: ``` dce708db8742fcb0e4a9d1f4c92781a7 ``` 

![[Image/[IMG]Valentine/37.png]]

## Post Exploit

- Upload the linpeas script and find the privilege escalation entry.
- Suspicious file in /root

![[Image/[IMG]Valentine/38.png]]
- Find the host using tmux 

![[Image/[IMG]Valentine/39.png]]
- Check ```.tmux.conf``` 

![[Image/[IMG]Valentine/40.png]]
- Try to check is there any suspend window, but failed
```
tmux at
tmux list
tmux ls 
tmux list-sessions
```

![[Image/[IMG]Valentine/41.png]]
- Check the bash history 

![[Image/[IMG]Valentine/42.png]]
- According to the bash history, I know the user move to ```.devs``` directory 
- And try to restore the tmux session by following command 
 
```
1. tmux -L dev_sess
2. tmux a -t dev_sess
3. tmux -S /.devs/dev_sess
```

![[Image/[IMG]Valentine/43.png]]
- This one will create a new session with hype permission
```
tmux -L dev_sess
```

### Privilege Escalation
- Reuse those command again, the only success one
```
tmux -S /.devs/dev_sess
```

![[Image/[IMG]Valentine/44.png]]
- Get into tmux session (dev_sess) in root permission 

![[Image/[IMG]Valentine/45.png]]
- Get root flag: ``` 82e61d3fb2924a6a22ea3324d371e4c3 ```

![[Image/[IMG]Valentine/46.png]]

## Reference 

### Writeup

- [(Github)Hackthebox- Valentine](https://github.com/Bengman/CTF-writeups/blob/master/Hackthebox/valentine.md)
- [Hackthebox- Valentine](https://resources.infosecinstitute.com/topic/hack-the-box-htb-machines-walkthrough-series-valentine/)
- [(YouTube)Hackthebox- Valentine](https://www.youtube.com/watch?v=XYXNvemgJUo)

### nmap vuln scan

- [How to Use Nmap for Vulnerability Scan?](https://geekflare.com/nmap-vulnerability-scan/)

### hearbleed attack

- [(Github)Heartbleed Attack explain](https://github.com/adamalston/Heartbleed)
- [(Github)PayloadsAllTheThings- CVEExploit-CVE-2014-0160](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Heartbleed%20CVE-2014-0160.py)
- [(Github)Heartbleed python exploit code](https://gist.github.com/eelsivart/10174134)
- [(Github)Heartbleed attack PoC](https://github.com/mpgn/heartbleed-PoC)

### Linux Bash command

- [Linux bash - base64 encode / decode](https://linuxhint.com/bash_base64_encode_decode/)
- [Linux bash - convert hex2ascii](https://www.baeldung.com/linux/character-hex-to-ascii)
- [Bash Display Web Page Content In Terminal](https://www.cyberciti.biz/faq/unix-linux-get-the-contents-of-a-webpage-in-a-terminal/)

### tmux related

- [tmux command](https://man7.org/linux/man-pages/man1/tmux.1.html)
- [Tmux Cheat Sheet & Quick Reference](https://tmuxcheatsheet.com/)
- [How to list and attach Tmux sessions](https://www.fosslinux.com/58718/list-and-attach-tmux-sessions.htm)
- [Tactical tmux: The 10 Most Important Commands](https://danielmiessler.com/study/tmux/)
- [Linux For Pentester: tmux Privilege Escalation](https://www.hackingarticles.in/linux-for-pentester-tmux-privilege-escalation/)

### Others

- [How to Find Files With SUID and SGID Permissions in Linux](https://www.tecmint.com/how-to-find-files-with-suid-and-sgid-permissions-in-linux/)
- [Linux Privilege Escalation Techniques via SUIDs](https://macrosec.tech/index.php/2021/06/08/linux-privilege-escalation-techniques-using-suid/)
- [How to use SSH keys for authentication](https://upcloud.com/resources/tutorials/use-ssh-keys-authentication)
- [Linux: How-To – Login with a SSH Private Key](https://www.cloudbolt.io/blog/linux-how-to-login-with-a-ssh-private-key/)
- [Linux file permission](https://www.hy-star.com.tw/tech/linux/permission/permission.html)


###### tags: `HackTheBox` `Easy` `linux` `heartbleed` `CVE-2014-0160`
