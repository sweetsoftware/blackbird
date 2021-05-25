# Blackbird

Network reconnaissance and enumeration tool.

## Install

Launch setup.py. This will install python requirements as well as module dependencies.

```
# Install python requirements
pip3 install -r requirements.txt

# Create symlink if wanted
ln -sf blackbird.py /usr/local/bin/blackbird

```

## Usage

Common usage examples:

```
# Scan whole subnet and store results in "bboutput"
blackbird -t 192.168.254.0/24 -w output

# Scan targets in targets.txt (one host/subnet by line), store output to a temp directory
blackbird -t targets.txt

# List modules
blackbrid --list-modules

# Scan all ports, noping (treat all hosts as alive), force rescan to override previous scan data and scan udp (requires root)
blackbird -t targets.txt --full -Pn --scan -w output --udp

# Run specifc module or tag
blackbird -t targets.txt -M mymodule,default,http

# Import nmap.xml into "bboutput" working dir, then scan it
blackbrid --nmap-import nmap.xml -w bboutput
blackbird -w bboutput
```



## Help

```
usage: blackbird [-h] [-t TARGET] [-w WORKING_DIR] [-U USERLIST] [-P PASSLIST] [-C USERPASSLIST] [-F] [--scan] [-Pn] [-p PORTS] [--nmap-import NMAP_IMPORT] [-M MODULES] [--udp] [--only-custom-brute]
                 [--search SEARCH] [--list-modules] [--dry-run]

Network reconnaissance and enumeration tool.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target list (comma seprated) or file with targets (one per line)
  -w WORKING_DIR, --working-dir WORKING_DIR
                        Working directory (created if does not exist)
  -U USERLIST, --userlist USERLIST
                        Custom userlist to try on all services
  -P PASSLIST, --passlist PASSLIST
                        Custom password list to try on all services
  -C USERPASSLIST, --userpasslist USERPASSLIST
                        User/password combinations (user:pass one by line)
  -F, --full            Full port scan (all ports checked)
  --scan                Force port scan (even if data exists, implied otherwise)
  -Pn                   Treat all hosts as alive
  -p PORTS, --ports PORTS
                        Only scan specific ports (comma separated)
  --nmap-import NMAP_IMPORT
                        Import nmap XML files (comma separated)
  -M MODULES, --modules MODULES
                        Run only selected modules (comma separated), or module tags
  --udp                 Scan UDP ports
  --only-custom-brute   Use only custom wordlists on bruteforce attempts
  --search SEARCH       Seach hosts by keyword, e.g "ldap", "Apache", ...
  --list-modules        List available modules
  --dry-run             Print commands but do not execute


```