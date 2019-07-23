import logging
import subprocess
import os
import glob
import shutil
import signal
import sys
import datetime
import fcntl

from bs4 import BeautifulSoup
import termcolor

from blackbird import config


logging.basicConfig(format='\n%(asctime)s::%(levelname)s::%(message)s',level=logging.DEBUG)
logging.getLogger().addHandler(logging.FileHandler(filename='output.log', mode='w'))


def run_cmd(cmdline, timeout=None, shell=True, wdir=None):
    log("Running command : %s" % cmdline)
    try:
        proc = subprocess.Popen(cmdline, shell=shell, cwd=wdir,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=1)
        proc_output = ""
        start_time = datetime.datetime.now().timestamp()
        proc_fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
        fcntl.fcntl(proc.stdout, fcntl.F_SETFL, proc_fl | os.O_NONBLOCK)
        while True:
            # Exit if timeout expired
            if timeout and (datetime.datetime.now().timestamp() - start_time) > timeout:
                log("Command timed out: %s" % cmdline, 'warning')
                break
            # Exit if process has returned
            if proc.poll() is not None:
                break
            output = proc.stdout.readline()
            # Print output if any
            if output:
                output = output.decode('utf8')
                sys.stdout.write(output)
                proc_output += output
        log(termcolor.colored('Command finished: ', 'green') + cmdline +
            '\n\n' + proc_output)
        return proc_output
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        log("Command execution timed out for '%s'" % cmdline, 'warning')


def log(log_str, log_type=''):
    if log_type == 'info':
        logging.info(termcolor.colored('[*] ' + log_str + "\n", 'green'))
    elif log_type == 'error':
        logging.critical(termcolor.colored('[!] ' + log_str + "\n", 'red'))
    elif log_type == 'warning':
        logging.warning(termcolor.colored('[!] ' + log_str + "\n", 'yellow'))
    else:
        logging.info(log_str)


def parse_nmap_xml(filename):
    host_info = dict()
    if not os.path.exists(filename):
        log("%s nmap XML not found" % filename, 'error')
        exit(1)
    xml_file = open(filename, 'r')
    soup = BeautifulSoup(xml_file, 'lxml')
    for host in soup.find_all('host'):
        host_addr = host.address['addr']
        host_domains = host.find_all('hostname')
        if host_domains:
            host_addr = host_domains[0]['name']
        if host_addr not in host_info:
            host_info[host_addr] = dict()
            host_info[host_addr]["tcp"] = dict()
            host_info[host_addr]["udp"] = dict()
        for port in host.find_all('port'):
            if port.state["state"] == "open":
                portid = port['portid']
                port_proto = port['protocol']
                host_info[host_addr][port_proto][portid] = dict()
                service = port.find("service")
                if service:
                    host_info[host_addr][port_proto][portid]['name'] = service.get('name') or ''
                    host_info[host_addr][port_proto][portid]['product'] = service.get('product') or ''
                    host_info[host_addr][port_proto][portid]['version'] = service.get('version') or ''
                    host_info[host_addr][port_proto][portid]['extrainfo'] = service.get('extrainfo') or ''
                    host_info[host_addr][port_proto][portid]['tunnel'] = service.get('tunnel') or ''
                    host_info[host_addr][port_proto][portid]['servicefp'] = service.get('servicefp') or ''
    return host_info


def find_services(nmap_file, search_string):
    host_info = parse_nmap_xml(nmap_file)
    matching_services = []
    search_string = search_string.lower()
    for host in host_info:
        for proto in host_info[host]:
            for port in host_info[host][proto]:
                service_info = host_info[host][proto][port]
                if not service_info:
                    continue
                if search_string in service_info['name'].lower() or \
                    search_string in service_info['product'].lower() or \
                        search_string in service_info['version'].lower() or \
                        search_string in service_info['extrainfo'].lower() or \
                        search_string == port:
                            service = "%s:%s - %s" % (host, port, " ".join([service_info['name'],service_info['product'],
                                                      service_info['version'], service_info['extrainfo']]))
                            matching_services.append(service)
    return matching_services


def merge_nmap_files(file_list, output_file):
    log("Merging %s ... " % file_list, 'info')
    output = open(output_file, 'w')
    XML_HEADER = ("""<?xml version="1.0" encoding="UTF-8"?>\n"""
    """<!DOCTYPE nmaprun>\n"""
    """<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n"""
    """<nmaprun scanner="nmap" args="Blackbird Summary" start="0" """
    """startstr="None" version="7.70" xmloutputversion="1.04">\n"""
    )
    output.write(XML_HEADER)
    for file in file_list:
        xml_file = open(file, 'r')
        soup = BeautifulSoup(xml_file, 'lxml')
        for host in soup.find_all('host'):
            output.write(str(host))
    output.write('\n</nmaprun>\n')
    output.close()


def split_nmap_file(nmap_xml_file, output_dir):
    for host in get_host_list(nmap_xml_file):
        host_xml = os.path.join(output_dir, host, "port-scan.xml")
        if os.path.exists(host_xml):
            os.remove(host_xml)

    XML_HEADER = ("""<?xml version="1.0" encoding="UTF-8"?>\n"""
                  """<!DOCTYPE nmaprun>\n"""
                  """<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n"""
                  """<nmaprun scanner="nmap" args="Blackbird Summary" start="0" """
                  """startstr="None" version="7.70" xmloutputversion="1.04">\n"""
                  )
    xml_file = open(nmap_xml_file, 'r')
    soup = BeautifulSoup(xml_file, 'lxml')
    for host in soup.find_all('host'):
        host_addr = host.address['addr']
        host_domains = host.find_all('hostname')
        if host_domains:
            host_addr = host_domains[0]['name']
        log('Extracting data for %s' % host_addr, 'info')
        host_dir = os.path.join(output_dir, host_addr)
        if not os.path.exists(host_dir):
            os.makedirs(host_dir)
        host_xml = os.path.join(host_dir, "port-scan.xml")
        if not os.path.exists(host_xml):
            host_file = open(host_xml, 'w')
            host_file.write(XML_HEADER)
        else:
            host_file = open(host_xml, 'a')
        host_file.write(str(host))
        host_file.close()
    xml_file.close()
    for host in get_host_list(nmap_xml_file):
        host_xml = os.path.join(output_dir, host, "port-scan.xml")
        with open(host_xml, 'a') as host_file:
            host_file.write('\n</nmaprun>\n')


def import_nmap_scans(nmap_xml_files, output_dir):
    log("Importing %s ..." % nmap_xml_files, 'info')
    for xml_file in nmap_xml_files:
        if not os.path.exists(xml_file):
            log("File does not exist: %s" % xml_file, 'error')
            return
    log("Creating output dir %s" % output_dir, 'info')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    sweep_file = os.path.join(output_dir, 'sweep.xml')
    merge_nmap_files(nmap_xml_files, sweep_file)
    update_nmap_summary([sweep_file])
    split_nmap_file(sweep_file, output_dir)
    log("Done importing into %s" % output_dir, 'info')


def update_nmap_summary(xml_files):
    nmap_summary_file = os.path.join(config.OUTPUT_PATH, 'nmap_summary.xml')
    if os.path.exists(nmap_summary_file):
        old_nmap_summary_file =  nmap_summary_file + ".old"
        shutil.copyfile(nmap_summary_file, old_nmap_summary_file)
        xml_files.append(old_nmap_summary_file)
    merge_nmap_files(xml_files, nmap_summary_file)


def get_host_list(nmap_xml):
    nmap_results = parse_nmap_xml(nmap_xml)
    return nmap_results.keys()


def get_module_list():
    module_list = glob.glob(os.path.join(config.INSTALL_DIR, 'blackbird/modules/', "*"))
    module_list =[os.path.basename(f) for f in module_list if
                  not (not os.path.isdir(f) or not os.path.exists(os.path.join(f, '__init__.py')))]
    return module_list
