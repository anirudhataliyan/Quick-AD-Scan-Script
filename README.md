# Python LDAP Scanner

I made this script to make my stuff easier, I've integrated vulnerabitiy scanner for **relay attacks** too, Thanks to [@timb-machine-mirrors](https://github.com/timb-machine-mirrors/GoSecure-ldap-scanner), but I didn't really checked it and repo looks old, if you guys have any other scanner, feel free to fork and try that, this is just a quick script for me, I'll add extra stuff when I came acess them, but for now I'm only using this only. And result get stored in CSV or JSON files, so it gets handy to view the overview of the network you're "enumerating". 

**This Script Incudes:**
1. Users Enumeration
2. Group Enumeration 
3. Computers in network
4. [Vulnerability scanner for relay attacks ](https://github.com/timb-machine-mirrors/GoSecure-ldap-scanner)
5. Use [Kerbrute](https://github.com/ropnop/kerbrute) to enumerate accounts. 


## Requirements
1. Python 3.8+
2. pip packages in requirements.txt
3. (Optional) kerbrute binary. Download releases from https://github.com/ropnop/kerbrute/releases and place the binary somewhere on your PATH or provide a full path.


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
## Kerbrute integration (new)
This project can call the [Kerbrute](https://github.com/ropnop/kerbrute) binary as an argument to perform fast Kerberos-based username enumeration/password spraying. There are three integration options:

1. Path to kerbrute binary — pass --kerbrute /path/to/kerbrute and the script will call kerbrute for requested operations and capture its output.
2. Bundled under `src/kerbrute` — if you've placed the kerbrute folder inside the src folder (for example `src/kerbrute/kerbrute`), the script will try that relative path by default when `--kerbrute` isn't provided.
3. Kerbrute disabled — default. The script will perform only LDAP-based enumeration.
4. The script will check the following paths (in order) when looking for the binary:

1. The --kerbrute path provided by the user.
2.`./src/kerbrute/kerbrute` (Unix) or `./src/kerbrute/kerbrute.exe` (Windows) relative to the project root.
3. Any kerbrute on the system **PATH**.

If the binary is found under src/kerbrute, you don't need to pass --kerbrute — the script will detect and use it automatically.
The script then parses kerbrute output lines for known tokens (e.g. VALID USERNAME:) and appends results to the CSV/JSON files alongside other enumerated objects.

A `--kerbrute-safe` flag will pass `--safe` to kerbrute to avoid locking accounts.

## Example CLI usage
```bash
# Enumerate users using kerbrute (username list file created by Quick-AD-Scan-Script)
$ python3 main.py --kerbrute ./src/kerbrute/kerbrute --kerbrute-cmd userenum --domain example.com --userlist usernames.txt
# If you've placed kerbrute inside src/kerbrute, the script will auto-detect it and this also works:
$ python3 main.py --kerbrute-cmd userenum --domain example.com --userlist usernames.txt
# Password spray via kerbrute using a single password against a userlist
$ python3 main.py --kerbrute ./src/kerbrute/kerbrute --kerbrute-cmd passwordspray --domain example.com --password 'Summer2025' --userlist usernames.txt --kerbrute-safe
```


## Note
I made this script for testing purpose only, please be careful and don't mess around in networks you're not allowed to. And I'll be glad if you guys help me to figure out what more I can do with this like adding new exploits and stuff, please feel free to raise issue. 
