import multiprocessing
import os
import signal
import psutil
import time
import termcolor
import select
import sys
import datetime
import asyncio

from blackbird import utils
from blackbird import config
from blackbird import modules


async def run(targets):
    utils.log('Initiating reconscan on targets : %s' % targets, 'info')
    
    for module in config.MODULES:
        utils.log("Running {} module ...".format(module), "info")
        module_obj = getattr(globals()['modules'], module)
        for target in targets:
            module_instances = []
            output_path = os.path.join(config.OUTPUT_PATH, target)
            nmap_xml_file = os.path.join(output_path, "port-scan.xml")
            if not os.path.exists(nmap_xml_file):
                utils.log("Couldn't find scan data for target : {}".format(target), 'warning')
                continue
            nmap_results = utils.parse_nmap_xml(nmap_xml_file)
            if not nmap_results:
                utils.log("No open ports on %s, skipping..." % target, "warning")
                continue
            for proto in ['tcp', 'udp']:
                for port in nmap_results[target][proto]:
                    if not nmap_results[target][proto][port]:
                        continue
                    service = nmap_results[target][proto][port]['name']
                    module_output_dir = os.path.join(output_path, proto + '-' + port + "-" + service)
                    module_instance = module_obj.ModuleInstance(target, port, service,  nmap_results[target][proto][port], module_output_dir, proto)
                    if module_instance.can_run():
                        if not os.path.exists(module_output_dir):
                            os.makedirs(module_output_dir)
                        module_instances.append(module_instance)
            await asyncio.gather(*(instance.run() for instance in module_instances))
