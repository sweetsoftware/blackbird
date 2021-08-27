import requests
requests.packages.urllib3.disable_warnings()
import aiohttp

from blackbird.core.module import Module
from blackbird.core import utils 
from blackbird.core import log


class HttpModule(Module):

    # module tag e.g default, brute, extra
    TAGS = ["http",]

    # Load module with target and service info
    def __init__(self, host, service, output_dir):
        Module.__init__(self, host, service, output_dir)
        self.tls = self.is_tls()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'


    def is_tls(self):
        if self.service == 'https':
            return True
        elif self.service.tunnel == 'ssl':
            return True
        elif self.service.port == '443':
            return True


    def get_url(self, hostname=None):
        host = hostname if hostname else self.host.address
        if self.tls:
            url = "https://" + host
            if self.service.port != 443:
                url += ":" + self.service.port
        else:
            url = "http://" + host
            if self.service.port != 80:
                url += ":" + self.service.port
        return url


    async def can_run(self):
        if self.service.transport == 'tcp' and (self.service.protocol in ['http', 'https']):
            return True
        # nmap doesn't mark some HTTP services as so, check the service response for HTTP
        # if service port is a common HTTP port, we also try to make an HTTP request directly
        elif "HTTP" in self.service.servicefp or \
            int(self.service.port) in [80, 443, 8080, 8443, 8000]:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.get(self.get_url(), verify=False, timeout=10)
                    return True
            except requests.exceptions.Timeout:
                log.warn('HTTP timeout: {}'.format(self.get_url()))
                return False
            except:
                return False
        return False
