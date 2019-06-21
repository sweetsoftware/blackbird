import logging
import subprocess
import os
import glob

from bs4 import BeautifulSoup
import termcolor

logging.basicConfig(level=logging.DEBUG)
logging.getLogger().addHandler(logging.FileHandler(filename='output.log', mode='w'))


def run_cmd(cmdline):
    log("Running command : %s" % cmdline, "info")
    subprocess.call(cmdline, shell=True)


def log(log_str, log_type=''):
    if log_type in ['info']:
        if log_type == 'info':
            logging.info(termcolor.colored('[*] ' + log_str + "\n", 'green'))
    else:
        logging.info(log_str)


def parse_nmap_xml(filename):
    log("Parsing nmap XML...", "info")
    host_info = dict()
    xml_file = open(filename, 'r')
    soup = BeautifulSoup(xml_file, 'lxml')
    for host in soup.find_all('host'):
        host_addr = host.address['addr']
        host_domains = host.find_all('hostname')
        if host_domains:
            host_addr = host_domains[0]['name']
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
    return host_info


def merge_nmap_files(file_list, output_file):
    log("Merging %s ... " % file_list)
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


def get_host_list(nmap_xml):
    nmap_results = parse_nmap_xml(nmap_xml)
    return nmap_results.keys()


def get_module_list():
    module_list = glob.glob(os.path.join('./blackbird/modules/', "*"))
    module_list =[os.path.basename(f) for f in module_list if
                  not (not os.path.isdir(f) or not os.path.exists(os.path.join(f, '__init__.py')))]
    return module_list
