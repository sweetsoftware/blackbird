# Blackbird

Network reconnaissance and enumeration tool.

## Install

Launch setup.py. This will install python requirements as well as module dependencies.

```
./setup.py
```

## Usage

Common usage examples:

```
# Full default recon (on IP block)
./blackbird.py -t 192.168.254.148/24 -w outputdir --sweep --scan --enum --brute

# Full default recon on all ports (targets file)
./blackbird.py -F -t targets.txt -w outputdir --sweep --scan --enum --brute

# Only ping sweep
./blackbird.py -t 192.168.254.148/24 -w outputdir --sweep

# Import all hosts listed in targets.txt regardless of ping response
./blackbird.py -t targets.txt -w outputdir --no-sweep

# Only port scan (requires ping sweep first to "outputdir")
./blackbird.py -w outputdir --scan

# Only enum (requires portscan first to "outputdir")
./blackbird.py -w outputdir --enum

# Only bruteforce (requires portscan first to "outputdir")
./blackbird.py -w outputdir --brute

# Import nmap XML output and perform enumeration
./blackbird.py -w outputdir --nmap-import 
./blackbird.py -w outputdir --enum

# Bruteforce modules with custom wordlists in addition to built-in wordlists
./blackbird.py -w outputdir --brute -U users.txt -P passwords.txt -C userpass.txt

# Run only specific modules (this will only run SSH bruteforce)
./blackbird.py -w outputdir --brute -M ssh

# List available modules
./blackbird.py --list-modules
```

During module execution, press **B + RETURN** to pause the scan and display the interactive menu.
This can be used to kill modules which are eating too much time.

```
2019-07-15 15:12:50,335::INFO::[*] Invoking interactive menu...

********************************************************************************
Running processes:

0 - PID=11981
CREATED=2019-07-15 15:12:48
CMD=['/bin/sh', '-c', "whatweb --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0' --color=never --log-brief=/mnt/hgfs/A/pentest/blackbird/out2/192.168.254.148/tcp/80-http/whatweb.txt http://192.168.254.148:80"]

1 - PID=11984
CREATED=2019-07-15 15:12:48
CMD=['/bin/sh', '-c', 'hydra -t 4 -v -L /mnt/hgfs/A/pentest/blackbird/blackbird/modules/ssh/ssh_usernames.txt -P /mnt/hgfs/A/pentest/blackbird/blackbird/modules/ssh/ssh_passwords.txt -I -e nsr -f ssh://192.168.254.148:22|tee /mnt/hgfs/A/pentest/blackbird/out2/192.168.254.148/tcp/22-ssh/brute.txt']

2 - PID=11986
CREATED=2019-07-15 15:12:48
CMD=['/bin/sh', '-c', 'wfuzz -Z -w /mnt/hgfs/A/pentest/blackbird/blackbird/modules/http/urls.txt -u http://192.168.254.148:80/FUZZ -L --hc 404 -f /mnt/hgfs/A/pentest/blackbird/out2/192.168.254.148/tcp/80-http/wfuzz.txt,raw']
********************************************************************************
Choose processes to kill (comma separated) (-1 to kill all): 0

2019-07-15 15:13:06,108::INFO::Killing pid 11979

2019-07-15 15:13:06,115::INFO::Resuming jobs...
```


## Help

```
usage: blackbird.py [-h] [-t TARGET] [-w WORKING_DIR] [--sweep] [--no-sweep]
                    [-U USERLIST] [-P PASSLIST] [-C USERPASSLIST] [-F]
                    [--enum] [--scan] [--brute] [--nmap-import NMAP_IMPORT]
                    [-M MODULES] [--only-custom-brute] [--list-modules]

Network reconnaissance and enumeration tool.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target (nmap format) or file with targets (one per
                        line)
  -w WORKING_DIR, --working-dir WORKING_DIR
                        Working directory (created if does not exist)
  --sweep               Ping sweep targets
  --no-sweep            Treat all hosts as alive (no ping sweep)
  -U USERLIST, --userlist USERLIST
                        Custom userlist to try on all services
  -P PASSLIST, --passlist PASSLIST
                        Custom password list to try on all services
  -C USERPASSLIST, --userpasslist USERPASSLIST
                        User/password combinations (user:pass one by line)
  -F, --full            Full port scan (all ports checked)
  --enum                Run service enumeration modules
  --scan                Perform port scan
  --brute               Run service bruteforce modules
  --nmap-import NMAP_IMPORT
                        Import nmap XML files (comma separated)
  -M MODULES, --modules MODULES
                        Run only selected modules (for --enum and --brute
                        operations)
  --only-custom-brute   --brute will run only custom wordlists on bruteforce
                        attempts
  --list-modules        List available modules

```
