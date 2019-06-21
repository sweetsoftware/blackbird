import os
import sys
import subprocess
import glob

from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):

    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)
        self.tls = self.is_tls(service, nmap_results)
        self.url = self.get_url(target, port, self.tls)


    def is_tls(self, service, nmap_results):
        tls = False
        if service == 'http':
            if nmap_results['tunnel'] == 'ssl':
                tls = True
        if service == 'https':
            tls = True
        return tls


    def get_url(self, target, port, tls):
        if tls:
            url = "https://" + target
            if port != 443:
                url += ":" + port
        else:
            url = "http://" + target
            if port != 80:
                url += ":" + port
        return url


    def can_run(self):
        if self.proto == 'tcp' and (self.service == 'http' or self.service == 'https'):
            return True
        return False


    def enum(self):
        utils.log('Starting HTTP enumeration against %s' % (self.url), 'info')
        
        cmd = "whatweb --color=never --log-brief=%s %s" % (self.get_output_path('whatweb.txt'), self.url)
        utils.run_cmd(cmd)
 
        cmd = "dirb %s %s -l -r -o %s" % (self.url, self.get_ressource_path('urls.txt'), self.get_output_path('dirb.txt'))
        utils.run_cmd(cmd)

        cmd = "xvfb-run -a cutycapt --url='%s' --out='%s'" % (self.url, self.get_output_path('screenshot.png'))
        utils.run_cmd(cmd)


    def do_bruteforce(self, outfile, user_list=None, pass_list=None, userpass_list=None):
        if user_list and pass_list:
            cmd = "hydra -L %s -P %s -I -e nsr -f -s %s %s http-get / |tee %s" % (user_list, pass_list, self.port, self.target, outfile)
        elif userpass_list:
            cmd = "hydra -C %s -I -e nsr -f -s %s %s http-get / |tee %s" % (userpass_list, self.port, self.target, outfile)
        utils.run_cmd(cmd)


    def brute(self):
        # Detect HTTP Basic authentication
        if 'WWW-Authenticate: Basic' not in subprocess.check_output('curl -kLI %s' % self.url, shell=True).decode('utf8'):
            return
        utils.log('Starting HTTP bruteforce against %s' % (self.url), 'info')

        user_list = self.get_ressource_path('users.txt')
        pass_list = self.get_ressource_path('pass.txt')
        outfile = self.get_output_path('brute.txt')
        self.do_bruteforce(outfile, user_list=user_list, pass_list=pass_list)

        if config.CUSTOM_USER_LIST:
            outfile = self.get_output_path('brute_custom1.txt')
            self.do_bruteforce(outfile, user_list=config.CUSTOM_USER_LIST, pass_list=config.CUSTOM_PASS_LIST)
        if config.CUSTOM_USERPASS_LIST:
            outfile = self.get_output_path('brute_custom2.txt')
            self.do_bruteforce(outfile, userpass_list=config.CUSTOM_USERPASS_LIST)
