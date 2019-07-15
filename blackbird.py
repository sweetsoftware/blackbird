#!/usr/bin/env python3

import argparse
import os
import traceback
import glob

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
    parser.add_argument('-w', '--working-dir', help='Working directory (created if does not exist)', required=True)
    parser.add_argument('--sweep', help='Ping sweep targets', action='store_true')
    parser.add_argument('--no-sweep', help='Treat all hosts as alive (no ping sweep)', action='store_true')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all service')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('-F', '--full', action='store_true', help='Full port scan (all ports checked)')
    parser.add_argument('--enum', action='store_true', help='Enumerate target')
    parser.add_argument('--scan', action='store_true', help='Perform port scan')
    parser.add_argument('--brute', action='store_true', help='Perform login bruteforce')
    parser.add_argument('--nmap-import', help='Import nmap XML files (comma separated)')
    parser.add_argument('-M', '--modules', help='Run only selected modules (for --enum and --brute operations)')
    parser.add_argument('--only-custom-brute', action='store_true', help='--brute will run only custom wordlists on bruteforce attempts')
    args = parser.parse_args()

    # Scan configuration
    config.NOSWEEP = args.no_sweep
    config.FULL_SCAN = args.full
    config.ENUM = args.enum
    config.BRUTE = args.brute
    config.SCAN = args.scan
    if os.path.isabs(args.working_dir):
        config.OUTPUT_PATH = args.working_dir
    else:
        config.OUTPUT_PATH = os.path.join(os.getcwd(), args.working_dir)
    if not os.path.exists(config.OUTPUT_PATH):
        os.makedirs(config.OUTPUT_PATH)
        utils.log('Created output directory %s.' % config.OUTPUT_PATH, 'info')
    config.SWEEP = args.sweep
    config.MODULES = utils.get_module_list()
    config.ONLY_CUSTOM_BRUTE = args.only_custom_brute

    if args.modules:
        config.MODULES=args.modules.split(',')
        installed_modules = utils.get_module_list()
        for i in config.MODULES:
            if i not in installed_modules:
                utils.log('Module not found: %s' % i, 'info')
                exit(1)
    if args.nmap_import:
        nmap_xml_files = []
        for path in args.nmap_import.split(','):
            nmap_xml_files += glob.glob(path)
        utils.import_nmap_scans(nmap_xml_files, config.OUTPUT_PATH)

    # Custom dictionnaries
    if args.userlist and not args.passlist or args.passlist and not args.userlist:
        utils.log('userlist and password list should be used together.')
        exit(1)
    if args.userlist:
        if os.path.exists(args.userlist) and os.path.isfile(args.userlist):
            config.CUSTOM_USER_LIST = args.userlist
        else:
            utils.log('No such file : %s' % args.userlist)
            exit(1)
        if os.path.exists(args.passlist) and os.path.isfile(args.passlist):
            config.CUSTOM_PASS_LIST = args.passlist
        else:
            utils.log('No such file : %s' % args.passlist)
            exit(1)
    if args.userpasslist:
        if os.path.exists(args.userpasslist) and os.path.isfile(args.userpasslist):
            config.CUSTOM_USERPASS_LIST = args.userpasslist
        else:
            utils.log('No such file : %s' % args.userpasslist)
            exit(1)
    if config.ONLY_CUSTOM_BRUTE and not (args.userlist or args.userpasslist):
        utils.log('No custom wordlist given for bruteforce.', 'info')
        exit(1)

    # Check options
    if not args.target and (args.sweep or args.no_sweep):
        utils.log('Targets (-t) is needed for sweep scan.', 'info')
        exit(1)
    if args.target and not (args.sweep or args.no_sweep):
        utils.log('Targets options (-t) is only processed when a new --sweep or --no-sweep scan is performed. Otherwise, the already existing sweep.xml file in the output dir is used to list targets.', 'info')
        exit(1)

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

    utils.log('Blackbird done.', 'info')

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        utils.log('Unhandled exception : %s' % exc)
        utils.log(traceback.format_exc())
