from blackbird.core import utils
from blackbird.core import config
from blackbird.core.module import Module
from blackbird.core import log


class ModuleInstance(Module):
    
    TAGS = ['default',]
    TYPE = "host"
    
    async def can_run(self):
        return True

    async def run(self):
        cmd = "whois '%s'" % self.host.address
        await utils.run_cmd(cmd, outfile=self.get_output_path("whois-{}.txt".format(self.host.address)))
        domains = set()
        for hostname in self.host.get_hostnames():
            domains.add(".".join(hostname.split(".")[-2:]))
        for domain in domains:
            cmd = "whois '%s'" % domain
            await utils.run_cmd(cmd, outfile=self.get_output_path("whois-{}.txt".format(domain)))
