
from blackbird import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):

    TAGS = ['http', 'default']

    async def run(self):
        for hostname in self.hostnames:
            cmd = "whatweb -v -a 3 --user-agent '%s' %s" % \
                (self.user_agent, self.get_url())
            output = await utils.run_cmd(cmd)
            outfile = self.get_output_path('whatweb-%s.txt' % hostname)
            with open(outfile, 'w') as out:
                out.write(output)
