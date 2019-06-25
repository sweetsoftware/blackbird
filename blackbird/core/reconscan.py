import multiprocessing
import os
import threading

from blackbird import utils
from blackbird import config
from blackbird import modules


def _recon_scan(target, output_dir):
    utils.log('Performing recon scan on target %s' % target, 'info')
    jobs = []
    output_path = os.path.join(output_dir, target)
    nmap_xml_file = os.path.join(output_path, "port-scan.xml")
    if not os.path.exists(nmap_xml_file):
        utils.log("No TCP scan file : %s Either no port is open or you didn't perform port scan (--scan)" % nmap_xml_file, 'info')
        return
    nmap_results = utils.parse_nmap_xml(nmap_xml_file)
    if not nmap_results:
        utils.log("No open ports on %s, skipping..." % target, "info")
        return
  
    for port in nmap_results[target]['tcp']:
        service = nmap_results[target]['tcp'][port]['name']
        output_dir = os.path.join(output_path, 'tcp', port + "-" + service)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        for module_name in config.MODULES:
            module_obj = getattr(globals()['modules'], module_name)
            module_instance = module_obj.ModuleInstance(target, port, service,  nmap_results[target]['tcp'][port], output_dir, 'tcp')
            if module_instance.can_run():
                if config.ENUM:
                    jobs.append(threading.Thread(target=module_instance.enum))
                if config.BRUTE:
                    jobs.append(threading.Thread(target=module_instance.brute))
    for i in jobs:
        utils.log("Starting job %s ..." % i, 'info')
        i.start()
    for i in jobs:
        utils.log("Waiting for job %s ..." % i, 'info')
        i.join(config.THREAD_TIMEOUT)


def run(output_dir):
    jobs = []
    sweep_file = os.path.join(output_dir, 'sweep.xml')
    if not os.path.exists(sweep_file):
        utils.log("Could not parse host list... have you performed a ping sweep first (--sweep) or specified the --no-sweep flag ? ", 'info')
        exit(1)
    for target in utils.get_host_list(sweep_file):
        scan_p = (target, output_dir)
        jobs.append(scan_p)
    pool = multiprocessing.Pool()
    pool.starmap(_recon_scan, jobs)
    pool.close()
    pool.join()
