import os
import inspect
import asyncio
import abc

from blackbird.core import utils
from blackbird.core import config


class Module:

    TYPE = "service"
    TAGS = ["default",]


    def __init__(self, host, service, output_dir):
        """ Load module with target and service info. """
        self.output_dir = output_dir
        self.module_dir = os.path.dirname(inspect.getfile(self.__class__))
        self.module_name = os.path.basename(inspect.getfile(self.__class__))[:-3]
        self.ressource_dir = os.path.join(self.module_dir, 'resources')
        self.is_bruteforce = False
        self.host = host
        self.service = service
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)


    def get_resource_path(self, filename):
        """ Get full path to a ressource file (e.g wordlist). """
        return os.path.join(self.ressource_dir, filename)


    def get_output_path(self, filename):
        """ Get full path to the module's output directory. """
        if self.TYPE == 'service':
            return os.path.join(self.output_dir, self.host.address + "-" + self.service.transport + "-" + str(self.service.port) + "-" + filename)
        elif self.TYPE == 'host':
            return os.path.join(self.output_dir, self.host.address + "-" + filename)


    async def can_run(self):
        """ Returns True if the module can run on this service, else False. """
        raise NotImplementedError("The can_run() method is not implemented in %s" % self.module_name)

    async def _run(self):
        """ Runs the module. """
        if await self.can_run():
            await self.run()

    async def run(self):
        """ Module logic. """
        raise NotImplementedError("The run() method is not implemented in %s" % self.module_name)
