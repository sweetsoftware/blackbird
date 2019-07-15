# Blackbird

Network reconnaissance and enumeration tool.

## Install

Launch setup.py. This will install python requirements as well as module dependencies.

```
./setup.py
```

## Usage

Common usage:

```
# Full recon
./blackbird.py -t 192.168.254.148/24 -o outputdir --sweep --scan --enum --brute

# Only ping sweep
./blackbird.py -t 192.168.254.148/24 -o outputdir --sweep

# Import all hosts listed in targets.txt regardless of ping response
./blackbird.py -t targets.txt -o outputdir --no-sweep

# Only port scan (requires ping sweep first to "outputdir")
./blackbird.py -o outputdir --scan

# Only enum (requires portscan first to "outputdir")
./blackbird.py -o outputdir --enum

# Only bruteforce (requires portscan first to "outputdir")
./blackbird.py -o outputdir --brute

```

## Help

```
root@kali:~/Blackbird# ./blackbird.py  --help

__________.__                 __   ___.   .__           .___
\______   \  | _____    ____ |  | _\_ |__ |__|______  __| _/
 |    |  _/  | \__  \ _/ ___\|  |/ /| __ \|  \_  __ \/ __ | 
 |    |   \  |__/ __ \\  \___|    < | \_\ \  ||  | \/ /_/ | 
 |______  /____(____  /\___  >__|_ \|___  /__||__|  \____ | 
        \/          \/     \/     \/    \/               \/     
    ./\.
  ./    `\.
  \.       `\.
    `\.       `\.
       `\.       `\.
          `\.       `\.
          ./           `\.
        ./            ____`\.
      ./                  <  `\.
      \-------\            `>   `\.
        `\=====>        ___<       `\.
       ./-----/             __________`\.
       \.------\       _____   ___(_)(_\.`\
         `\=====>          <            ./'
        ./-----/            `>        ./
        \.               ___<       ./
          `\.                     ./
             `\.                ./
                `\.           ./
                ./          ./
              ./          ./ 
            ./          ./
          ./          ./
        ./          ./
        \.        ./
          `\.   ./
             `\/
(Artwork by Carl Pilcher)
    
usage: blackbird.py [-h] -t TARGET -o OUTPUT [--sweep] [--no-sweep]
                    [-U USERLIST] [-P PASSLIST] [-C USERPASSLIST] [-F]
                    [--enum] [--scan] [--brute]

Network reconnaissance and enumeration tool.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target (nmap format) or file with targets (one per
                        line)
  -o OUTPUT, --output OUTPUT
                        Output directory (created if does not exist)
  --sweep               Ping sweep targets
  --no-sweep            Treat all hosts as alive (no ping sweep)
  -U USERLIST, --userlist USERLIST
                        Custom userlist to try on all services
  -P PASSLIST, --passlist PASSLIST
                        Custom password list to try on all service
  -C USERPASSLIST, --userpasslist USERPASSLIST
                        User/password combinations (user:pass one by line)
  -F, --fast            Fast scan (not all ports checked)
  --enum                Enumerate target
  --scan                Perform port scan
  --brute               Perform login bruteforce

```
