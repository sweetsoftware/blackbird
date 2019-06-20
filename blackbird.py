#!/usr/bin/env python3

import argparse
import os
import traceback

from blackbird import core
from blackbird import utils
from blackbird import config


def main():
    print(r"""
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
    """)
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.")
    parser.add_argument('-t', '--target', help='Target (nmap format) or file with targets (one per line)')
    parser.add_argument('-o', '--output', help='Output directory (created if does not exist)', required=True)
    parser.add_argument('--sweep', help='Ping sweep targets', action='store_true')
    parser.add_argument('--no-sweep', help='Treat all hosts as alive (no ping sweep)', action='store_true')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all service')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('-F', '--fast', action='store_true', help='Fast scan (not all ports checked)')
    parser.add_argument('--enum', action='store_true', help='Enumerate target')
    parser.add_argument('--scan', action='store_true', help='Perform port scan')
    parser.add_argument('--brute', action='store_true', help='Perform login bruteforce')
    args = parser.parse_args()

    # Scan configuration
    config.NOSWEEP = args.no_sweep
    config.FAST_SCAN = args.fast
    config.ENUM = args.enum
    config.BRUTE = args.brute
    config.SCAN = args.scan
    config.OUTPUT_PATH = args.output
    config.SWEEP = args.sweep

    # Custom dictionnaries
    if args.userlist and not args.passlist or args.passlist and not args.userlist:
        print('userlist and password list should be used together.')
        exit(1)
    if args.userlist:
        if os.path.exists(args.userlist) and os.path.isfile(args.userlist):
            config.CUSTOM_USER_LIST = args.userlist
        else:
            print('No such file : %s' % args.userlist)
            exit(1)
        if os.path.exists(args.passlist) and os.path.isfile(args.passlist):
            config.CUSTOM_PASS_LIST = args.passlist
        else:
            print('No such file : %s' % args.passlist)
            exit(1)
    if args.userpasslist:
        if os.path.exists(args.userpasslist) and os.path.isfile(args.userpasslist):
            config.CUSTOM_USERPASS_LIST = args.userpasslist
        else:
            print('No such file : %s' % args.userpasslist)
            exit(1)
    
    # Check options
    if not args.target and (args.sweep or args.no_sweep):
        utils.log('Targets (-t) is needed for sweep scan.', 'info')
        exit(1)
    if args.target and not (args.sweep or args.no_sweep):
        utils.log('Targets options (-t) is only processed when a new --sweep or --no-sweep scan is performed. Otherwise, the already existing sweep.xml file in the output dir is used to list targets.', 'info')
        exit(1)

    # Output directory handling
    if not os.path.exists(config.OUTPUT_PATH):
        os.mkdir(config.OUTPUT_PATH)
        utils.log('Created output directory %s.' % config.OUTPUT_PATH, 'info')

    # Load targets
    if args.target:
        targets = args.target
        if os.path.exists(targets) and os.path.isfile(targets):
            targets_file = targets
            with open(targets_file, 'r') as f:
                targets = ' '.join(f.readlines()).replace('\n', '')
        utils.log("Parsed targets : " + targets, 'info')

    output_path = config.OUTPUT_PATH
    # Do sweep scan or import all targets
    if config.NOSWEEP:
        core.nosweep.run(targets, output_path)
    elif config.SWEEP:
        core.sweep.run(targets, output_path)

    if config.SCAN:
        # Do port scan
        core.portscan.run(output_path)

    if config.ENUM or config.BRUTE:
        # Do recon scan
        core.reconscan.run(output_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        utils.log('Unhandled exception : %s' % exc)
        utils.log(traceback.format_exc())
