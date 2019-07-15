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
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'

    def is_tls(self, service, nmap_results):
        tls = False
        if service == 'https':
            tls = True
        elif nmap_results['tunnel'] == 'ssl':
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
        # nmap doesn't mark some HTTP services as so, check the servicefp attribute
        elif "HTTP" in self.nmap_results["servicefp"]:
            return True
        return False


    def enum(self):
        utils.log('Starting HTTP enumeration against %s' % (self.url), 'info')

        # Fingerprint web technologies
        cmd = "whatweb --user-agent '%s' --color=never --log-brief=%s %s" % \
              (self.user_agent, self.get_output_path('whatweb.txt'), self.url)
        utils.run_cmd(cmd, timeout=20)

        # Screenshot web page
        cmd = "chromium --ignore-certificate-errors  --headless --no-sandbox --window-size=1920,1080 --screenshot='%s' '%s'" % \
              (self.get_output_path("screenshot.png"), self.url)
        utils.run_cmd(cmd, timeout=10)


    def do_bruteforce(self, outfile, user_list=None, pass_list=None, userpass_list=None):
        if self.tls:
            method = 'https-get'
        else:
            method = 'http-get'
        if user_list and pass_list:
            cmd = "hydra -L %s -P %s -I -e nsr -f -s %s %s %s / |tee %s" % (user_list, pass_list, self.port, self.target, method, outfile)
        elif userpass_list:
            cmd = "hydra -C %s -I -f -s %s %s %s / |tee %s" % (userpass_list, self.port, self.target, method, outfile)
        utils.run_cmd(cmd, wdir=self.output_dir)


    def brute(self):
        # Bruteforce URLs
        cmd = "wfuzz -Z -w %s -u %s/FUZZ -L --hc 404 -f %s,raw" % (self.get_ressource_path('urls.txt'),
            self.url, self.get_output_path('wfuzz.txt'))
        utils.run_cmd(cmd)

        # Detect and bruteforce HTTP Basic authentication
        if 'WWW-Authenticate: Basic' not in subprocess.check_output('curl -kLI %s' % self.url, shell=True).decode('utf8'):
            return
        utils.log('Starting HTTP bruteforce against %s' % (self.url), 'info')

        user_list = self.get_ressource_path('http_users.txt')
        pass_list = self.get_ressource_path('http_passwords.txt')
        userpass_list = self.get_ressource_path('http_userpass.txt')
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
