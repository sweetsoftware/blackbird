from blackbird.core import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):
    
    TAGS = ['http', 'default']
    TYPE = "service"
    
    async def run(self):
        for hostname in self.host.get_hostnames(include_ip=True):
            cmd = "whatweb -v -a 3 --user-agent '%s' %s" % \
                (self.user_agent, self.get_url(hostname=hostname))
            await utils.run_cmd(cmd, outfile=self.get_output_path("whatweb-%s.txt" % hostname))
