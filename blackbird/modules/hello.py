from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):

    def can_run(self):
        return True

    async def run(self):
        utils.log('Running hello world module against %s:%s' % (self.target, self.port), 'info')
