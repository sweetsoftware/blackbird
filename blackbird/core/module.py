import os
import inspect
import abc

from blackbird import utils
from blackbird import config

class Module:

    # module tag e.g default, brute, extra
    TAGS = ["default",]

    # Load module with target and service info
    def __init__(self, target, port, service, nmap_results, output_dir, proto, hostnames):
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
        self.hostnames = set(hostnames)
        self.hostnames.add(target)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)


    # Get full path to a ressource file (e.g wordlist)
    def get_resource_path(self, filename):
        return os.path.join(self.ressource_dir, filename)

    # Get full path to the module's output directory
    def get_output_path(self, filename):
        return os.path.join(self.output_dir, self.target + "-" + self.proto + "-" + self.port + "-" + filename)

    # Check if the module can run on this service
    async def can_run(self):
        return True

    # Run the module
    async def _run(self):
        can_run = await self.can_run()
        if can_run:
            await self.run()

    async def run(self):
        raise NotImplementedError("The run() method is not implemented in %s" % self.module_dir)
