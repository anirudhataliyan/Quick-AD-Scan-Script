# Python LDAP Scanner

I made this script to make my stuff easier, I've integrated vulnerabitiy scanner for **relay attacks** too, Thanks to [@timb-machine-mirrors](https://github.com/timb-machine-mirrors/GoSecure-ldap-scanner), but I didn't really checked it and repo looks old, if you guys have any other scanner, feel free to fork and try that, this is just a quick script for me, I'll add extra stuff when I came acess them, but for now I'm only using this only. And result get stored in CSV or JSON files, so it gets handy to view the overview of the network you're "enumerating". 

**This Script Incudes:**
1. Users Enumeration
2. Group Enumeration 
3. Computers in network
4. [Vulnerability scanner for relay attacks ](https://github.com/timb-machine-mirrors/GoSecure-ldap-scanner)

## Installation
```
$ pip install -r requirements.txt
$ python3 main.py
```

## Usage
```
$ python main.py 
Welcome to Active Directory Enumerator

Enter the Active Directory server address (e.g., ldap://domain.com): example.edu
Enter the username (e.g., DOMAIN\\User): user1
Enter the password: password

Connection successful!

Enter the search base (e.g., DC=domain,DC=com): com
Enumerating objects in the directory...

---- SKIPPPED ---
```

## Note
I made this script for testing purpose only, please be careful and don't mess around in networks you're not allowed to. And I'll be glad if you guys help me to figure out what more I can do with this like adding new exploits and stuff, please feel free to raise issue. 