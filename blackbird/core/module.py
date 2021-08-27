import os
import inspect
import asyncio
import abc

from blackbird.core import utils
from blackbird.core import config

class Module:

    # module tag e.g default, brute, extra
    TAGS = ["default",]

    # Load module with target and service info
    def __init__(self, host, service, output_dir):
        self.output_dir = output_dir
        self.module_dir = os.path.dirname(inspect.getfile(self.__class__))
        self.module_name = os.path.basename(inspect.getfile(self.__class__))[:-3]
        self.ressource_dir = os.path.join(self.module_dir, 'resources')
        self.is_bruteforce = False
        self.host = host
        self.service = service
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)


    # Get full path to a ressource file (e.g wordlist)
    def get_resource_path(self, filename):
        return os.path.join(self.ressource_dir, filename)

    # Get full path to the module's output directory
    def get_output_path(self, filename):
        return os.path.join(self.output_dir, self.host.address + "-" + self.service.transport + "-" + self.service.port + "-" + filename)

    # Check if the module can run on this service
    async def can_run(self):
        raise NotImplementedError("The can_run() method is not implemented in %s" % self.module_name)

    # Run the module
    async def _run(self):
        if await self.can_run():
            await self.run()

    async def run(self):
        raise NotImplementedError("The run() method is not implemented in %s" % self.module_name)
