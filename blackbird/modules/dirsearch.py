from blackbird import utils
from blackbird.core.http_module import HttpModule


class ModuleInstance(HttpModule):

    TAGS = ['http', 'default']

    async def run(self):
        for hostname in self.hostnames:
            outfile = self.get_output_path('dirsearch-%s.txt' % hostname)
            cmd = "dirsearch -b -q --random-agent -u %s -o '%s'" % \
                (self.get_url(hostname), outfile)
            output = await utils.run_cmd(cmd)
            # with open(outfile, 'w') as out:
            #     out.write(output)
