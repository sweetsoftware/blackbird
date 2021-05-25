import requests
requests.packages.urllib3.disable_warnings()

from .module import Module
from blackbird import utils 


class HttpModule(Module):

    # module tag e.g default, brute, extra
    TAGS = ["http",]

    # Load module with target and service info
    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)
        self.tls = self.is_tls(service, nmap_results)
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'
        self.hostnames = utils.get_hostnames(self.target)


    def is_tls(self, service, nmap_results):
        if service == 'https':
            return True
        elif nmap_results['tunnel'] == 'ssl':
            return True
        elif self.port == '443':
            return True


    def get_url(self, hostname=None):
        host = hostname if hostname else self.target
        if self.tls:
            url = "https://" + host
            if self.port != 443:
                url += ":" + self.port
        else:
            url = "http://" + host
            if self.port != 80:
                url += ":" + self.port
        return url


    def can_run(self):
        if self.proto == 'tcp' and (self.service == 'http' or self.service == 'https'):
            return True
        # nmap doesn't mark some HTTP services as so, check the service response for HTTP
        # if service port is a common HTTP port, we also try to make an HTTP request directly
        elif "HTTP" in self.nmap_results["servicefp"] or \
            int(self.port) in [80, 443, 8080, 8443, 8000, 8443]:
            try:
                req = requests.get(self.get_url(), verify=False, timeout=5)
            except requests.exceptions.Timeout:
                utils.log('Service not responding: {}'.format(self.get_url()))
                return False
            return True
        return False
    
    # Run the module
    async def run(self):
        raise NotImplementedError("The run() method is not implemented in %s" % self.module_dir)
