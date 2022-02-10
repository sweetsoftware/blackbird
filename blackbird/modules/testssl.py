from blackbird.core import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):
    
    TAGS = ['http', 'default']
    TYPE = "service"
    
    async def can_run(self):
        return await HttpModule.can_run(self) and self.tls

    async def run(self):
        cmd = "testssl {}:{}".format(self.host.address, self.service.port)
        await utils.run_cmd(cmd, outfile=self.get_output_path("testssl.txt"))
