# Blackbird

Network reconnaissance and enumeration tool.

## Install


```
# Install python requirements
pip3 install -r requirements.txt

# Create symlink if wanted
ln -sf blackbird.py /usr/local/bin/blackbird

```

## Help

```
# ./Blackbird.py -h
usage: Blackbird.py [-h] [-i INPUT_FILES] [-o OUTPUT_DIR] [-M MODULES] [-t TARGETS] [-H HOST_FILE] [-U USERLIST] [-P PASSLIST] [-C USERPASSLIST] [--brute-type {default,custom}] [--search SEARCH] [--list-modules] [--dry-run]
                    [-c MAX_CONCURRENCY] [--no-logo] [--cmd-timeout CMD_TIMEOUT]

Network reconnaissance and enumeration tool.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FILES, --input-files INPUT_FILES
                        Import nmap XML files (comma separated)
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Store results there
  -M MODULES, --modules MODULES
                        Run only selected modules (comma separated), or module tags
  -t TARGETS, --targets TARGETS
                        Comma separated list of targets. Will only scan these.
  -H HOST_FILE, --host-file HOST_FILE
                        Hostnames file
  -U USERLIST, --userlist USERLIST
                        Custom userlist to try on all services
  -P PASSLIST, --passlist PASSLIST
                        Custom password list to try on all services
  -C USERPASSLIST, --userpasslist USERPASSLIST
                        User/password combinations (user:pass one by line)
  --brute-type {default,custom}
                        Bruteforce type: default (default wordlists + any custom wordlist) or custom (only custom wordlists)
  --search SEARCH       Seach hosts by keyword, e.g "ldap", "Apache", ...
  --list-modules        List available modules
  --dry-run             Print commands but do not execute
  -c MAX_CONCURRENCY, --max-concurrency MAX_CONCURRENCY
                        Max concurrent tasks
  --no-logo             Hide logo
  --cmd-timeout CMD_TIMEOUT
                        Timeout for external commands (seconds)
```
