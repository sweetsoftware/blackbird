import os
import glob
import asyncio
import tempfile
import termcolor

from blackbird.core import config
from blackbird.core import utils
from blackbird.core import log
from blackbird import modules
from blackbird.core.exceptions import BlackBirdError
from blackbird.core.host import Host


class BlackBird():

    def __init__(self, input_files=None,
        brute_type='default', user_list=None, pass_list=None, userpass_list=None,
        search=None, modules='default', output_dir=None, host_file=None, targets=None,
        cmd_timeout=60*15, show_logo=True, max_tasks=10, dry_run=False):

        self.INSTALL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
        if cmd_timeout:
            config.CMD_TIMEOUT = int(cmd_timeout)
        if not show_logo:
            config.SHOW_LOGO = False
        if max_tasks:
            config.MAX_TASKS = int(max_tasks)
        if dry_run:
            config.DRY_RUN = True
        self.search_str = search
        self.modules_to_load = modules.split(',')

        # Output directory
        if output_dir:
            self.output_dir = output_dir
            if os.path.exists(self.output_dir):
                log.warn("Output dir already exists.")
            else:
                try:
                    os.makedirs(self.output_dir)
                except:
                    raise BlackBirdError("Output dir could not be created: " + self.output_dir)
        else:
            self.output_dir = tempfile.mkdtemp()
        
        # Import nmap files
        self.hosts = dict()
        if input_files:    
            nmap_xml_files = []
            for path in input_files.split(','):
                nmap_xml_files.append(path)
            self.load_nmap_xml_files(nmap_xml_files)

        # Target specification
        self.targets = targets
        if self.targets:
            self.targets = [_.replace(" ", "") for _ in targets.split(",")]
            for target in self.targets:
                if target not in self.hosts:
                    for host in self.hosts:
                        if target not in self.hosts[host].get_hostnames():
                            raise BlackBirdError("Target " + target + " is not in scan data.")

        # Import hostnames
        if host_file:
            self.load_hostnames(host_file)

        # Bruteforce type
        if brute_type not in ['custom', 'default']:
            raise BlackBirdError("Invalid brute type %s" % brute_type)
        config.BRUTE_TYPE = brute_type

        # Load custom dictionnaries
        config.CUSTOM_USER_LIST = user_list
        config.CUSTOM_PASS_LIST = pass_list
        config.CUSTOM_USERPASS_LIST = userpass_list
        if user_list or pass_list:
            if not (os.path.exists(user_list) and os.path.isfile(user_list)):
                raise BlackBirdError('No such user list : %s' % user_list)
            if not (os.path.exists(pass_list) and os.path.isfile(pass_list)):
                raise BlackBirdError('No such password list : %s' % pass_list)
        if userpass_list:
            if not (os.path.exists(userpass_list) and os.path.isfile(userpass_list)):
                raise BlackBirdError('No such userpass list : %s' % userpass_list)
    

    def load_hostnames(self, host_file):
        """ Loads hostnames from file and adds them to the associated hosts. """
        if not os.path.exists(host_file):
            raise BlackBirdError("File does not exist: %s" % host_file)
        try:
            with open(host_file, "r") as hfile:
                for line in hfile.read().splitlines():
                    address = line.split(" ")[0]
                    hostnames = line.split(" ")[1:]
                    if address in self.hosts:
                        self.hosts[address].add_hostnames(hostnames)
                    else:
                        log.warn("Address in hosts file but not in scan data: " + address)
        except Exception as exc:
            raise BlackBirdError("Error parsing host file: " + str(exc))


    def load_nmap_xml_files(self, nmap_xml_files):
        """ Load hosts data from file. """
        for xml_file in nmap_xml_files:
            if not os.path.exists(xml_file):
                raise BlackBirdError("File does not exist: %s" % xml_file)
            parsed = utils.parse_nmap_xml(xml_file)
            if not parsed:
                raise BlackBirdError("No scan data in file: " + xml_file)
            for address, host_data in parsed.items():
                self.hosts[address] = Host(address, host_data)
        if not self.hosts:
            raise BlackBirdError("No scan data in input files")


    async def recon_scan(self):
        """ Run modules. """
        log.info('Initiating reconscan')
        self.modules = self.load_modules(self.modules_to_load)
        tasks = []
        # Iterate through modules
        for module_name, module_obj in self.modules.items():
            # Iterate through hosts
            for address, host in self.hosts.items():
                # Find if current host is in the targets
                if self.targets and address not in self.targets:
                    for hostname in host.get_hostnames():
                        if hostname in self.targets:
                            break
                    else:
                        continue
                module_output_dir = os.path.join(self.output_dir, module_name)
                if module_obj.ModuleInstance.TYPE == 'host':
                    module_instance = module_obj.ModuleInstance(host, None, module_output_dir)
                    tasks.append(module_instance)
                elif module_obj.ModuleInstance.TYPE == 'service':
                    for service in host.services:
                        module_instance = module_obj.ModuleInstance(host, service, module_output_dir)
                        tasks.append(module_instance)
        log.info("Now running {} modules ...".format(len(tasks)))
        await asyncio.gather(*(instance._run() for instance in tasks))


    async def run(self):
        """ Run instance. """
        if config.SHOW_LOGO:
            self.print_logo()
        if self.hosts:
            if self.search_str:
                self.search(self.search_str)
                return
            else:
                log.info("Running ... output dir: " + self.output_dir)
                await self.recon_scan()
                log.info("Done. Output in " + self.output_dir)
        else:
            raise BlackBirdError("No hosts to process.")


    def find_services(self, search_string):
        """ Search hosts services for a string and return matching services. """
        search_string = search_string.lower()
        matching_services = set()
        for host in self.hosts.values():
            for service in host.services:
                if search_string == '*' or service.search(search_string):
                    matching_services.add(service)
        return matching_services


    def load_modules(self, modules_to_load):
        """ Return module objects dict by name from module and tag list. """
        modules_by_tag = dict()
        module_list = self.get_module_list()
        
        log.info("Loading modules")

        # Build module object dict form module list
        for module_name in module_list:
            module_obj = getattr(globals()['modules'], module_name)
            module_tags = module_obj.ModuleInstance.TAGS
            for tag in module_tags:
                if tag not in modules_by_tag:
                    modules_by_tag[tag] = dict()
                modules_by_tag[tag][module_name] = module_obj

        modules = dict()
        # Load all modules
        if "all" in modules_to_load:
            for tag in modules_by_tag:
                for module_name in modules_by_tag[tag]:
                    log.info("Loaded module : %s" % module_name)
                    modules[module_name] = modules_by_tag[tag][module_name]
            return modules
        # Load specific modules by name or tag
        for module_or_tag in modules_to_load:
            module_or_tag = module_or_tag.lower()
            # Load modules by matching name
            for tag in modules_by_tag:
                if module_or_tag in modules_by_tag[tag]:
                    modules[module_or_tag] = modules_by_tag[tag][module_or_tag]
                    log.info("Loaded module : %s" % module_or_tag)
                    break
            # Load modules by matching tag (if no module matching by name)
            else:
                if module_or_tag in modules_by_tag:
                    for i in modules_by_tag[module_or_tag]:
                        log.info("Loaded module : %s [%s]" % (i, module_or_tag))
                        modules[i] = modules_by_tag[module_or_tag][i]
                else:
                    raise BlackBirdError('Could not find module or tag named "%s"' % module_or_tag)
        return modules

    
    def search(self, search_str):
        """ Search feature. """
        print(termcolor.colored('Services matching "%s" : ' % search_str, 'green'))
        print('-' * 30)
        for result in self.find_services(search_str):
            print(result)


    def get_module_list(self):
        """ List installed modules. """
        module_list = glob.glob(os.path.join(self.INSTALL_DIR, 'blackbird/modules/', "*.py"))
        module_list = [ os.path.basename(f)[:-3] for f in module_list if os.path.isfile(f) and not f.endswith('__init__.py')]
        return module_list


    def print_logo(self):
        print(r"""
    ____  _            _    _     _         _ 
    | __ )| | __ _  ___| | _| |__ (_)_ __ __| |
    |  _ \| |/ _` |/ __| |/ / '_ \| | '__/ _` |
    | |_) | | (_| | (__|   <| |_) | | | | (_| |
    |____/|_|\__,_|\___|_|\_\_.__/|_|_|  \__,_|
    """)
