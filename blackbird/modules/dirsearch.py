from blackbird.core import utils
from blackbird.core.http_module import HttpModule

import asyncio


class ModuleInstance(HttpModule):
    
    TAGS = ['http', 'default']
    TYPE = "service"
    
    async def run(self):
        for hostname in self.host.get_hostnames(include_ip=True):
            cmd = "dirsearch -b -q -u '%s' -o '%s'" % (self.get_url(hostname), self.get_output_path('dirsearch-%s.txt' % hostname))
            await utils.run_cmd(cmd)
