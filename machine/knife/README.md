## Reconnaissance

### nmap 

![](./IMG/0.png)

### Web Server 

![](./IMG/1.png)

> Check web version 

![](./IMG/3.png)

> Gobuster to brute force the directory 

![](./IMG/2.png)


> Check the request and response 
> Got more detail version for PHP 

```
php 8.1.0-dev
```

![](./IMG/4.png)

> Search Exploit code 

```
searchsploit php | grep 8.1.0-dev
```

![](./IMG/5.png)
> Just in Case, I search another exploit code from github

- [(GITHUB)hp-8.1.0-dev-backdoor-rce](https://github.com/flast101/php-8.1.0-dev-backdoor-rce)

![](./IMG/6.png)
## Exploit 

> Use the exploit code 
> I get the low-lever permission in target

```
python 49933.py
```

![](./IMG/7.png)
> Get user flag

![](./IMG/10.png)


## Privilege Escalation 

> Check current user 

![](./IMG/8.png)
> Check sudo permission 

```
sudo -l
```

![](./IMG/9.png)
> Check current ip address

![](./IMG/11.png)
> Since the current shell is not quite convenience
> Try to get another shell back to my host
> but failed

![](./IMG/12.png)

> I tried to follow GTFobins to get root privilege by /usr/bin/knife
> but still failed

![](./IMG/13.png)

> So I change to another exploit code from github 

![](./IMG/14.png)

> Get another shell on port 1338

![](./IMG/15.png)
> Check current user - root 


![](./IMG/16.png)

> Get root flag

![](./IMG/17.png)

## Reference 

- [(GTFOBins)Knife](https://gtfobins.github.io/gtfobins/knife/)
- [PHP 8.1.0-dev Backdoor Remote Code Execution (RCE)](https://vk9-sec.com/php-8-1-0-dev-backdoor-remote-code-execution-rce/)
- [(ExploitDB)php-8.1.0-dev](https://www.exploit-db.com/exploits/49933)
- [php-8.1.0-dev-backdoor-rce](https://flast101.github.io/php-8.1.0-dev-backdoor-rce/)
- [(GITHUB)hp-8.1.0-dev-backdoor-rce](https://github.com/flast101/php-8.1.0-dev-backdoor-rce)

###### tags: `HackTheBox`