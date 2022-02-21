import requests
requests.packages.urllib3.disable_warnings()
import aiohttp
import asyncio

from blackbird.core.module import Module
from blackbird.core import utils 
from blackbird.core import log


TAGS = ["http",]


class HttpModule(Module):
    
    def __init__(self, host, service, output_dir):
        Module.__init__(self, host, service, output_dir)
        self.tls = False
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'

    def is_tls(self):
        """ Returns ture if the service is TLS encrypted. """
        return self.tls

    def get_url(self, hostname=None):
        """ Returns full URL to the HTTP service. """
        url = ""
        if self.tls:
            url += "https://"
        else:
            url += "http://"
        if hostname:
            url += hostname
        else:
            url += self.host.address
        if self.tls and self.service.port != 443 or (not self.tls) and self.service.port != 80:
            url += ":" + str(self.service.port)
        return url

    async def can_run(self):
        try:
            url = "https://" + self.host.address + ":" + str(self.service.port)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                resp = await asyncio.wait_for(session.get(url, allow_redirects=False), timeout=5)
                self.tls = True
                return True
        except Exception as exc:
            await session.close()
            try:
                url = "http://" + self.host.address + ":" + str(self.service.port)
                async with aiohttp.ClientSession() as session:
                    resp = await asyncio.wait_for(session.get(url, allow_redirects=False), timeout=5)
                    self.tls = False
                    return True
            except:
                return False
