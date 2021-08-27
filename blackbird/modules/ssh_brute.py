import asyncio

from blackbird.core import utils
from blackbird.core import config
from blackbird.core.module import Module
from blackbird.core import log

from blackbird.core.basic_bruteforce import BasicBruteforceModule


class ModuleInstance(BasicBruteforceModule):

    TAGS = ["brute",]
 
    default_user_list = 'ssh-usernames.txt'
    default_pass_list = 'ssh-passwords.txt'
    default_userpass_list = 'ssh-userpass.txt'
    output_file_prefix = "hydra"

    async def can_run(self):
        if self.service.transport == 'tcp' and self.service.protocol == 'ssh':
            return True
        return False


    async def bruteforce_user_pass(self, user_list, pass_list, outfile):
        cmd = "hydra -t 4 -v -L %s -P %s -I -e nsr -f ssh://%s:%s" % (user_list, pass_list, self.host.address, self.service.port)
        await utils.run_cmd(cmd, outfile=self.get_output_path(outfile))


    async def bruteforce_userpass(self, userpass_list, outfile):
        cmd = "hydra -t 4 -v -C %s -I -f ssh://%s:%s" % (userpass_list, self.host.address, self.service.port)
        await utils.run_cmd(cmd, outfile=self.get_output_path(outfile))
