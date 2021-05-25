#!/usr/bin/env python3

import argparse
import os
import traceback
import glob
import shutil
import signal
import asyncio
import random
import string
import tempfile
import termcolor

from blackbird import core
from blackbird import utils
from blackbird import config
from blackbird import modules


def load_modules(modules_to_load):
    
    module_dict = dict()
    module_list = utils.get_module_list()
    
    for module_name in module_list:
        module_obj = getattr(globals()['modules'], module_name)
        module_tags = module_obj.ModuleInstance.TAGS
        for tag in module_tags:
            if tag not in module_dict:
                module_dict[tag] = []
            module_dict[tag].append(module_name)

    config.MODULES = set()
    
    if "all" in modules_to_load:
        config.MODULES = module_list
        return

    for module_or_tag in modules_to_load:
        module_or_tag = module_or_tag.lower()
        if module_or_tag in module_list:
            config.MODULES.add(module_or_tag)
            utils.log("Loading module : %s" % module_or_tag, 'info')
        elif module_or_tag in module_dict:
            for i in module_dict[module_or_tag]:
                utils.log("Loading module : %s [%s]" % (i, module_or_tag), 'info')
                config.MODULES.add(i)
        else:
            utils.log('Could not find module or tag named "%s"' % module_or_tag, 'error')
            exit(1)


def create_working_dir(working_dir):
    if not working_dir:
        working_dir = tempfile.mkdtemp()
        utils.log("No working dir set, using %s" % working_dir, 'info')
        # Implying scan
        config.SCAN = True
    if os.path.isabs(working_dir):
        config.OUTPUT_PATH = working_dir
    else:
        config.OUTPUT_PATH = os.path.join(os.getcwd(), working_dir)
    if not os.path.exists(config.OUTPUT_PATH):
        if not config.SCAN:
            utils.log("No hosts in working dir.", "info")
            config.SCAN = True
        os.makedirs(config.OUTPUT_PATH)
        utils.log('Created output directory %s' % config.OUTPUT_PATH, 'info')
    utils.setup_logfile()


async def load_targets(targets_arg):
    if not targets_arg:
            utils.log("No targets specified, reading targets from working dir ...", "info")
            targets = utils.get_host_list()
    else:
        # create targets.txt
        target_file = os.path.join(config.OUTPUT_PATH, 'targets.txt')
        if os.path.exists(targets_arg) and os.path.isfile(targets_arg):
            shutil.copyfile(targets_arg, target_file)
        else:
            with open(target_file, 'w') as f:
                for i in targets_arg.split(','):
                    f.write(i + "\n")
        # Expand networks into targets.xml
        xml_targets = os.path.join(config.OUTPUT_PATH, 'targets.xml')
        if config.NO_PING:
            list_scan = 'nmap -n -sL -oX %s -iL %s' % (xml_targets, target_file)
        else:
            list_scan = 'nmap -n -sn -oX %s -iL %s' % (xml_targets, target_file)
        await utils.run_cmd(list_scan, print_output=False)
        targets = list(utils.parse_nmap_xml(xml_targets).keys())
        utils.log("Parsed targets : %s" % targets, 'info')
        os.remove(target_file)
        os.remove(xml_targets)
    return targets

def parse_args(args):
    # Parse command line args
    config.FULL_SCAN = args.full
    config.UDP_SCAN = args.udp
    config.SCAN = args.scan
    config.DRY_RUN = args.dry_run
    config.ONLY_CUSTOM_BRUTE = args.only_custom_brute
    config.NO_PING = args.Pn
    if args.ports:
        config.PORTS = args.ports
        for port in args.ports.split(","):
            if not port.isdigit():
                utils.log("Invalid ports argument, should be comma separated integers", "error")
                exit(1)
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


async def main():
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-t', '--target', help='Target list (comma seprated) or file with targets (one per line)')
    parser.add_argument('-w', '--working-dir', help='Working directory (created if does not exist)')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all services')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('-F', '--full', action='store_true', help='Full port scan (all ports checked)')
    parser.add_argument('--scan', action='store_true', help='Force port scan (even if data exists, implied otherwise)')
    parser.add_argument('-Pn', action='store_true', help='Treat all hosts as alive')
    parser.add_argument('-p', '--ports', help='Only scan specific ports (comma separated)')
    parser.add_argument('--nmap-import', help='Import nmap XML files (comma separated)')
    parser.add_argument('-M', '--modules', default="default", help='Run only selected modules (comma separated), or module tags')
    parser.add_argument('--udp', action='store_true', help='Scan UDP ports')
    parser.add_argument('--only-custom-brute', action='store_true',
                        help='Use only custom wordlists on bruteforce attempts')
    parser.add_argument('--search', help='Seach hosts by keyword, e.g "ldap", "Apache", ...')
    parser.add_argument('--list-modules', action='store_true',
                        help='List available modules')
    parser.add_argument('--dry-run', action='store_true', help='Print commands but do not execute')
    args = parser.parse_args()

    if config.SHOW_LOGO:
        print(termcolor.colored(utils.get_logo(), 'blue'))

    # Load args in config
    parse_args(args)

    # Print available modules
    if args.list_modules:
        print(termcolor.colored('Module list : ', 'green'))
        print("-" * 30)
        for module in utils.get_module_list():
            print(module)
        return

    create_working_dir(args.working_dir)

    # Search feature
    if args.search:
        nmap_path = os.path.join(config.OUTPUT_PATH, 'nmap_summary.xml')
        print(termcolor.colored('Services matching "%s" : ' % args.search, 'green'))
        print('-' * 30)
        for result in utils.find_services(nmap_path, args.search):
            print(result)
        return

    # Import nmap file
    if args.nmap_import:
        nmap_xml_files = []
        for path in args.nmap_import.split(','):
            nmap_xml_files += glob.glob(path)
        utils.import_nmap_scans(nmap_xml_files, config.OUTPUT_PATH)
        exit(0)

    #############################################################
    if args.target:
        load_modules(args.modules.split(","))
        targets = await load_targets(args.target)

    # Do port scan
    if args.target and config.SCAN:
        await core.portscan.run(targets)

    # Do recon scan
    targets_to_scan = []
    if args.target and not config.SCAN:
        known_targets = utils.get_host_list()
        for target in targets:
            if target not in known_targets:
                utils.log('Target not previously scanned : %s was added to scan queue' % target, 'warning')
                targets_to_scan.append(target)
        if targets_to_scan:
            await core.portscan.run(targets_to_scan)
    await core.reconscan.run(utils.get_host_list())

    utils.log('Done. Results stored in %s' % config.OUTPUT_PATH, 'info')


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        utils.log('Unhandled exception : %s' % exc, 'error')
        utils.log(traceback.format_exc())
