import os
import inspect
import abc

from blackbird import utils


class Module:

    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        self.target = target
        self.port = port
        self.service = service
        self.nmap_results = nmap_results
        self.output_dir = output_dir
        self.proto = proto
        self.module_dir = os.path.dirname(inspect.getfile(self.__class__))
        self.product = nmap_results['product']
        self.version = nmap_results['version']
        self.extrainfo = nmap_results['extrainfo']
        self.tunnel = nmap_results['tunnel']
        self.servicefp = nmap_results['servicefp']

    def get_resource_path(self, filename):
        return os.path.join(self.module_dir, filename)

    def get_output_path(self, filename):
        return os.path.join(self.output_dir, filename)

    def can_run(self):
        raise NotImplementedError("The can_run() method is not implemented in %s" % self.module_dir)

    def enum(self):
        utils.log("The enum() method is not implemented in %s" % self.module_dir, 'warning')

    def brute(self):
        utils.log("The brute() method is not implemented in %s" % self.module_dir, 'warning')
