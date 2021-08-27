

class Service():

    def __init__(self, host, port, service, protocol, 
        tunnel, product, version, extrainfo, servicefp):
        self.host = host
        self.port = port
        self.protocol = service
        self.transport = protocol
        self.tunnel = tunnel
        self.product = product
        self.version = version
        self.extrainfo = extrainfo
        self.servicefp = servicefp


    def search(self, search_string):
        searchable = [self.host.address, self.protocol, self.version, self.product, self.extrainfo, self.servicefp]
        for field in searchable:
            if search_string in field:
                return True
        if search_string == self.port:
            return True
        for hostname in self.host.get_hostnames():
            if search_string in hostname:
                return True
        return False


    def __str__(self):
        return self.host.address + ":" + self.port + " " + self.transport


class Host():

    def __init__(self, address, scan_data, hostnames=[]):
        self.address = address
        self.hostnames = set()
        self.services = set()
        for hostname in hostnames:
            self.hostnames.add(hostname)
        self.hostnames.add(address)
        for proto in scan_data:
            for port, port_data in scan_data[proto].items():
                self.services.add(
                    Service(
                        host=self,
                        port=port,
                        service=port_data["name"],
                        protocol=proto,
                        tunnel=port_data["tunnel"],
                        product=port_data["product"],
                        version=port_data["version"],
                        extrainfo=port_data["extrainfo"],
                        servicefp=port_data["servicefp"]
                    )
                )

    
    def get_hostnames(self):
        return self.hostnames


    def add_hostname(self, hostname):
        self.hostnames.add(hostname)


    def add_hostnames(self, hostnames):
        for hostname in hostnames:
            self.add_hostname(hostname)