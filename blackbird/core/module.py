import os
import inspect
import abc

from blackbird import utils
from blackbird import config

class Module:

    # module tag e.g default, brute, extra
    TAGS = ["default",]

    # Load module with target and service info
    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        self.target = target
        self.port = port
        self.service = service
        self.nmap_results = nmap_results
        self.output_dir = output_dir
        self.proto = proto
        self.module_dir = os.path.dirname(inspect.getfile(self.__class__))
        self.ressource_dir = os.path.join(self.module_dir, 'resources')
        self.product = nmap_results['product']
        self.version = nmap_results['version']
        self.extrainfo = nmap_results['extrainfo']
        self.tunnel = nmap_results['tunnel']
        self.servicefp = nmap_results['servicefp']
        self.is_bruteforce = False

    # Get full path to a ressource file (e.g wordlist)
    def get_resource_path(self, filename):
        return os.path.join(self.ressource_dir, filename)

    # Get full path to the module's output directory
    def get_output_path(self, filename):
        return os.path.join(self.output_dir, filename)

    # Check if the module can run on this service
    def can_run(self):
        raise NotImplementedError("The can_run() method is not implemented in %s" % self.module_dir)

    # Run the module
    async def run(self):
        raise NotImplementedError("The run() method is not implemented in %s" % self.module_dir)
