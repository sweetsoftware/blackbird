#!/usr/bin/env python3

import argparse
import os
import traceback
import glob
import shutil
import signal

import termcolor

from blackbird import core
from blackbird import utils
from blackbird import config


LOGO = r"""
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
"""

def main():
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=LOGO)
    parser.add_argument('-t', '--target', help='Target (nmap format) or file with targets (one per line)')
    parser.add_argument('-w', '--working-dir', help='Working directory (created if does not exist)')
    parser.add_argument('--no-sweep', help='Treat all hosts as alive (no ping sweep)', action='store_true')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all services')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('-F', '--full', action='store_true', help='Full port scan (all ports checked)')
    parser.add_argument('--enum', action='store_true', help='Run service enumeration modules')
    parser.add_argument('--scan', action='store_true', help='Perform port scan')
    parser.add_argument('--brute', action='store_true', help='Run service bruteforce modules')
    parser.add_argument('--nmap-import', help='Import nmap XML files (comma separated)')
    parser.add_argument('-M', '--modules', help='Run only selected modules (for --enum and --brute operations)')
    parser.add_argument('--only-custom-brute', action='store_true',
                        help='--brute will run only custom wordlists on bruteforce attempts')
    parser.add_argument('--search', help='Find hosts running a particular '
                                         'service, e.g "ldap", "Apache", ...')
    parser.add_argument('--list-modules', action='store_true',
                        help='List available modules')
    args = parser.parse_args()

    if args.list_modules:
        print("Available modules:")
        print("=" * 20)
        for module in utils.get_module_list():
            print("*", module)
        exit(0)

    if not args.working_dir:
        parser.print_help()
        print("")
        utils.log("-w/--working-dir parameter missing", 'error')
        exit(1)

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
        utils.log('Created output directory %s' % config.OUTPUT_PATH, 'info')
    config.MODULES = utils.get_module_list()
    config.ONLY_CUSTOM_BRUTE = args.only_custom_brute

    if args.search:
        nmap_path = os.path.join(config.OUTPUT_PATH, 'nmap_summary.xml')
        print(termcolor.colored('%s services:' % args.search, 'green'))
        print('=' * 30)
        for result in utils.find_services(nmap_path, args.search):
            print(result)
        exit(0)

    # Module selection
    if args.modules:
        config.MODULES=args.modules.split(',')
        installed_modules = utils.get_module_list()
        for i in config.MODULES:
            if i not in installed_modules:
                utils.log('Module not found: %s' % i, 'error')
                exit(1)

    # Import nmap file
    if args.nmap_import:
        nmap_xml_files = []
        for path in args.nmap_import.split(','):
            nmap_xml_files += glob.glob(path)
        utils.import_nmap_scans(nmap_xml_files, config.OUTPUT_PATH)

    # Custom dictionnaries
    if args.userlist and not args.passlist or args.passlist and not args.userlist:
        utils.log('userlist and password list should be used together', 'error')
        exit(1)
    if args.userlist:
        if os.path.exists(args.userlist) and os.path.isfile(args.userlist):
            config.CUSTOM_USER_LIST = args.userlist
        else:
            utils.log('No such file : %s' % args.userlist, 'error')
            exit(1)
        if os.path.exists(args.passlist) and os.path.isfile(args.passlist):
            config.CUSTOM_PASS_LIST = args.passlist
        else:
            utils.log('No such file : %s' % args.passlist, 'error')
            exit(1)
    if args.userpasslist:
        if os.path.exists(args.userpasslist) and os.path.isfile(args.userpasslist):
            config.CUSTOM_USERPASS_LIST = args.userpasslist
        else:
            utils.log('No such file : %s' % args.userpasslist, 'error')
            exit(1)
    if config.ONLY_CUSTOM_BRUTE and not (args.userlist or args.userpasslist):
        utils.log('No custom wordlist given for bruteforce', 'error')
        exit(1)

    # Load targets file
    if args.target:
        target_file = os.path.join(config.OUTPUT_PATH, 'targets.txt')
        targets = args.target
        if os.path.exists(targets) and os.path.isfile(targets):
            shutil.copyfile(targets, target_file)
        else:
            with open(target_file, 'w') as f:
                for i in targets.split(' '):
                    f.write(i + "\n")
        config.TARGET_FILE = target_file
        utils.log("Parsed targets : " + targets, 'info')

    # Ignore SIGINT
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    output_path = config.OUTPUT_PATH
    if config.TARGET_FILE:
        # Do sweep scan or import all targets (no sweep)
        if config.NOSWEEP:
            core.nosweep.run(config.TARGET_FILE, output_path)
        else:
            core.sweep.run(config.TARGET_FILE, output_path)
    else:
        nmap_summary = os.path.join(output_path, "nmap_summary.xml")
        if os.path.exists(nmap_summary) and os.path.isfile(nmap_summary):
            shutil.copyfile(nmap_summary, os.path.join(output_path, 'sweep.xml'))
            utils.log('Targeting all hosts discovered so far', 'info')
        else:
            utils.log('Provide targets (-t) to scan at least for the first scan', 'error')
            exit(1)
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
        utils.log('Unhandled exception : %s' % exc, 'error')
        utils.log(traceback.format_exc())
