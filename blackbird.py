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


class BlackBird():

    def __init__(self, input_files=None,
        brute_type='default', user_list=None, pass_list=None, userpass_list=None,
        search=None, modules='default', output_dir=None, host_file=None):
        
        self.INSTALL_DIR = os.path.dirname(os.path.realpath(__file__))
        self.search_str = search
        self.modules = self.load_modules(modules.split(","))
        if output_dir:
            self.output_dir = output_dir
            if os.path.exists(self.output_dir) and os.path.isdir(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                except:
                    raise Exception("Output dir could not be created: " + self.output_dir)
        else:
            self.output_dir = tempfile.mkdtemp()
        
        # Import nmap files
        self.scan_data = None
        if input_files:    
            nmap_xml_files = []
            for path in input_files.split(','):
                nmap_xml_files += glob.glob(path)
            self.scan_data = self.load_nmap_xml_files(nmap_xml_files)

        # Import hostnames
        if host_file:
            self.load_hostnames(host_file)

        # Bruteforce type
        if brute_type not in ['custom', 'default']:
            raise Exception("Invalid brute type %s" % brute_type)
        self.brute_type = brute_type

        # Load custom dictionnaries
        self.CUSTOM_USER_LIST = user_list
        self.CUSTOM_PASS_LIST = pass_list
        self.CUSTOM_USERPASS_LIST = userpass_list
        if user_list or pass_list:
            if not (os.path.exists(user_list) and os.path.isfile(user_list)):
                raise Exception('No such user list : %s' % user_list)
            if not (os.path.exists(pass_list) and os.path.isfile(pass_list)):
                utils.log('No such file : %s' % pass_list, 'error')
                raise Exception('No such password list : %s' % pass_list)
        if userpass_list:
            if not (os.path.exists(userpass_list) and os.path.isfile(userpass_list)):
                raise Exception('No such userpass list : %s' % userpass_list)
    

    def load_hostnames(self, host_file):
        with open(host_file, "r") as hfile:
            for line in hfile.read().splitlines():
                address = line.split(" ")[0]
                hostnames = [_.replace(" ", "") for _ in (" ".join(line.split(" ")[1:])).split(",")]
                if address in self.scan_data:
                    self.scan_data[address]["hostnames"] = hostnames


    def load_nmap_xml_files(self, nmap_xml_files):
        scan_data = dict()
        for xml_file in nmap_xml_files:
            if not os.path.exists(xml_file):
                utils.log("File does not exist: %s" % xml_file, 'error')
                continue
            parsed = utils.parse_nmap_xml(xml_file)
            for host in parsed:
                parsed[host]["hostnames"] = []
            scan_data.update(parsed)
        return scan_data


    async def recon_scan(self):
        utils.log('Initiating reconscan', 'info')
        module_instances = []
        for module in self.modules:
            utils.log("Running {} module ...".format(module), "info")
            module_obj = getattr(globals()['modules'], module)
            for target in self.scan_data:
                for proto in ['tcp', 'udp']:
                    for port in self.scan_data[target][proto]:
                        if not self.scan_data[target][proto][port]:
                            continue
                        service = self.scan_data[target][proto][port]['name']
                        module_output_dir = os.path.join(self.output_dir, module)
                        module_instance = module_obj.ModuleInstance(
                            target, port, service,
                            self.scan_data[target][proto][port],
                            module_output_dir, proto, self.scan_data[target]["hostnames"])
                        module_instances.append(module_instance)
        await asyncio.gather(*(instance._run() for instance in module_instances))


    async def run(self):
        utils.log("Running ... output dir: " + self.output_dir, 'info')
        if self.search_str:
            self.search(self.search_str)
            return
        await self.recon_scan()


    def find_services(self, host_info, search_string):
        """ Search nmap scan for string and return matching services. """
        search_string = search_string.lower()
        for host in host_info:
            for proto in host_info[host]:
                for port in host_info[host][proto]:
                    service_info = host_info[host][proto][port]
                    if not service_info:
                        continue
                    if search_string in service_info['name'].lower() or \
                        search_string in service_info['product'].lower() or \
                            search_string in service_info['version'].lower() or \
                            search_string in service_info['extrainfo'].lower() or \
                            search_string in service_info['servicefp'].lower() or \
                            search_string == port:
                                service = "%s:%s - %s" % (host, port, " ".join([service_info['name'],service_info['product'],
                                                        service_info['version'], service_info['extrainfo']]))
                                yield service


    def load_modules(self, modules_to_load):
        module_dict = dict()
        module_list = self.get_module_list()
        
        for module_name in module_list:
            module_obj = getattr(globals()['modules'], module_name)
            module_tags = module_obj.ModuleInstance.TAGS
            for tag in module_tags:
                if tag not in module_dict:
                    module_dict[tag] = []
                module_dict[tag].append(module_name)

        modules = set()
        
        if "all" in modules_to_load:
            modules = module_list
            return

        for module_or_tag in modules_to_load:
            module_or_tag = module_or_tag.lower()
            if module_or_tag in module_list:
                modules.add(module_or_tag)
                utils.log("Loading module : %s" % module_or_tag, 'info')
            elif module_or_tag in module_dict:
                for i in module_dict[module_or_tag]:
                    utils.log("Loading module : %s [%s]" % (i, module_or_tag), 'info')
                    modules.add(i)
            else:
                utils.log('Could not find module or tag named "%s"' % module_or_tag, 'error')
                exit(1)
        return modules

    
    def search(self, search_str):
        print(termcolor.colored('Services matching "%s" : ' % search_str, 'green'))
        print('-' * 30)
        for result in self.find_services(self.scan_data, search_str):
            print(result)
        return


    def get_module_list(self):
        """ List installed modules. """
        module_list = glob.glob(os.path.join(self.INSTALL_DIR, 'blackbird/modules/', "*.py"))
        module_list = [ os.path.basename(f)[:-3] for f in module_list if os.path.isfile(f) and not f.endswith('__init__.py')]
        return module_list


async def main():
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-t', '--target', help='Target list (comma seprated) or file with targets (one per line)')
    parser.add_argument('-o', '--output-dir', help='Store results there')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all services')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('-i', '--input-files', help='Import nmap XML files (comma separated)')
    parser.add_argument('-H', '--host-file', help='Hostnames file')
    parser.add_argument('-M', '--modules', default="default", help='Run only selected modules (comma separated), or module tags')
    parser.add_argument('--only-custom-brute', action='store_true',
                        help='Use only custom wordlists on bruteforce attempts')
    parser.add_argument('--search', help='Seach hosts by keyword, e.g "ldap", "Apache", ...')
    parser.add_argument('--list-modules', action='store_true',
                        help='List available modules')
    parser.add_argument('--dry-run', action='store_true', help='Print commands but do not execute')
    args = parser.parse_args()

    blackbird = BlackBird(
        input_files=args.input_files,
        host_file=args.host_file,
        search=args.search,
        output_dir=args.output_dir,
        modules=args.modules)
    await blackbird.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        utils.log('Unhandled exception : %s' % exc, 'error')
        utils.log(traceback.format_exc())
