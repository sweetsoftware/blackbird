from blackbird.core import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):

    TAGS = ['http', 'default']

    async def run(self):
        for hostname in self.host.get_hostnames():
            cmd = "gospider -s '%s'" % \
                (self.get_url(hostname))
            await utils.run_cmd(cmd, outfile=self.get_output_path("gospider-%s.txt" % hostname))
