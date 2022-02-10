from blackbird.core import utils
from blackbird.core import config
from blackbird.core.module import Module
from blackbird.core import log


class ModuleInstance(Module):
    
    TAGS = ['hello',]
    TYPE = "service"    
    
    async def can_run(self):
        return True


    async def run(self):
        log.info('Running hello world module against %s:%s' % (self.host.address, self.service.port))
