import asyncio

from blackbird.core import utils
from blackbird.core import config
from blackbird.core.module import Module
from blackbird.core import log


class BasicBruteforceModule(Module):

    TAGS = ["brute",]
    # Override these in the subclassed module
    default_user_list = None
    default_pass_list = None
    default_userpass_list = None
    output_file_prefix = 'brute'

    def __init__(self, host, service, output_dir):
        Module.__init__(self, host, service, output_dir)


    async def run(self):
        user_list = None
        pass_list = None
        userpass_list = None
        if self.default_user_list and self.default_pass_list:
            user_list = self.get_resource_path(self.default_user_list)
            pass_list = self.get_resource_path(self.default_pass_list)
        if self.default_userpass_list:
            userpass_list = self.get_resource_path(self.default_userpass_list)
        tasks = []
        # Run default bruteforce
        if config.BRUTE_TYPE != 'custom':
            if user_list and pass_list:
                tasks.append(self.bruteforce_user_pass(user_list=user_list, pass_list=pass_list, outfile=self.output_file_prefix + "-default-user-pass.txt"))
            if userpass_list:
                tasks.append(self.bruteforce_userpass(userpass_list=userpass_list, outfile=self.output_file_prefix + "-default-userpass.txt"))
        # Custom lists
        if config.CUSTOM_USER_LIST and config.CUSTOM_PASS_LIST:
            tasks.append(self.bruteforce_user_pass(user_list=config.CUSTOM_USER_LIST, pass_list=config.CUSTOM_PASS_LIST,
                outfile=self.output_file_prefix + "-custom-user-pass.txt"))
        if config.CUSTOM_USERPASS_LIST:
            tasks.append(self.bruteforce_userpass(userpass_list=config.CUSTOM_USERPASS_LIST,
                outfile=self.output_file_prefix + "-custom-userpass.txt"))
        await asyncio.gather(*tasks)


    async def bruteforce_user_pass(self, user_list, pass_list, outfile):
        raise NotImplementedError("The bruteforce_user_pass() method is not implemented in %s" % self.module_name)


    async def bruteforce_userpass(self, userpass_list, outfile):
        raise NotImplementedError("The bruteforce_userpass() method is not implemented in %s" % self.module_name)
    

    async def do_bruteforce(self, outfile, user_list=None, pass_list=None, userpass_list=None):
        if user_list and pass_list:
            cmd = "hydra -t 4 -v -L %s -P %s -I -e nsr -f ssh://%s:%s" % (user_list, pass_list, self.host.address, self.service.port)
        elif userpass_list:
            cmd = "hydra -t 4 -v -C %s -I -f ssh://%s:%s" % (userpass_list, self.host.address, self.service.port)
        await utils.run_cmd(cmd, outfile=self.get_output_path(outfile))
