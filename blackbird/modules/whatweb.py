
from blackbird import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):

    TAGS = ['http', 'default']

    async def run(self):
        for hostname in self.hostnames:
            cmd = "whatweb -v -a 1 --user-agent '%s' %s" % \
                (self.user_agent, self.get_url(hostname=hostname))
            await utils.run_cmd(cmd, outfile=self.get_output_path("whatweb-%s.txt"% hostname))
