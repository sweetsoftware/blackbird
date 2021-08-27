import logging
import subprocess
import os
import glob
import shutil
import signal
import sys
import datetime
import asyncio
import glob
import os

from bs4 import BeautifulSoup
import termcolor

from blackbird import config


logging.basicConfig(format='%(message)s',level=logging.INFO)


async def run_cmd(cmdline, timeout=config.CMD_TIMEOUT, print_output=True, wdir=None, outfile=None):
    """Run a command asynchronously and return output
    Enforce a timeout and max conccurent processes run by the program
    """
    while len(config.RUNNING_PROCS) >= config.MAX_TASKS:
        # Too many tasks running, sleeping for some time
        await asyncio.sleep(1)
    config.RUNNING_PROCS.append(cmdline)
    log("Running : {}".format(cmdline), 'info')
    try:
        if not config.DRY_RUN:
            proc = await asyncio.create_subprocess_shell(
                cmdline,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                executable=os.environ["SHELL"])
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = ""
            if stdout:
                stdout = stdout.decode('cp850' if os.name == 'nt' else 'utf8')
                if stdout:
                    output += str(stdout)
            if stderr:
                stderr = stderr.decode('cp850' if os.name == 'nt' else 'utf8')
                if stderr:
                    output += str(stderr)
            if print_output:
                log("Output for : {}".format(cmdline), 'info')
                log(output)
            config.RUNNING_PROCS.remove(cmdline)
            if config.RUNNING_PROCS:
                log("%s tasks running ..." % len(config.RUNNING_PROCS), "info")
            if outfile:    
                with open(outfile, 'w') as out:
                    out.write(output)
            return output
        else:
            config.RUNNING_PROCS.remove(cmdline)
            return ""
    except asyncio.TimeoutError:
        log("Command execution timed out : {}".format(cmdline), 'warning')
    except Exception as exc:
        if cmdline in config.RUNNING_PROCS:
            config.RUNNING_PROCS.remove(cmdline)
        log("Command execution failed : {}\n{}".format(cmdline, exc), 'warning')


# Output message to the logs
def log(log_str, log_type=''):
    if log_type == 'info':
        logging.info(termcolor.colored('[I] ' + log_str, 'green'))
    elif log_type == 'error':
        logging.critical(termcolor.colored('[E] ' + log_str, 'red'))
    elif log_type == 'warning':
        logging.warning(termcolor.colored('[W] ' + log_str, 'yellow'))
    else:
        logging.info(log_str)


# Read nmap XML output and returns dict
def parse_nmap_xml(filename):
    host_info = dict()
    if not os.path.exists(filename):
        log("%s nmap XML not found" % filename, 'error')
        exit(1)
    xml_file = open(filename, 'r')
    soup = BeautifulSoup(xml_file, 'lxml')
    for host in soup.find_all('host'):
        host_addr = host.address['addr']
        hostnames = host.find_all('hostname')
        for hostname in hostnames:
            if hostname['type'] == 'user':
                host_addr = hostname['name']
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


def merge_nmap_files(file_list, output_file):
    """ Merge a list of nmap scans into one file. """
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


def update_nmap_summary(xml_files):
    """ Add multiple scan files results to the main nmap file. """
    nmap_summary_file = os.path.join(config.OUTPUT_PATH, 'nmap_summary.xml')
    if os.path.exists(nmap_summary_file):
        old_nmap_summary_file =  nmap_summary_file + ".old"
        shutil.copyfile(nmap_summary_file, old_nmap_summary_file)
        xml_files.append(old_nmap_summary_file)
        merge_nmap_files(xml_files, nmap_summary_file)
        os.remove(old_nmap_summary_file)
    else:
        merge_nmap_files(xml_files, nmap_summary_file)


def split_nmap_file(nmap_xml_file, output_dir):
    """ Split a nmap scan into per host scan files. """
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
        for domain in host_domains:
            if domain['type'] == 'user':
                host_addr = domain['name']
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
    for host in get_host_list():
        host_xml = os.path.join(output_dir, host, "port-scan.xml")
        with open(host_xml, 'a') as host_file:
            host_file.write('\n</nmaprun>\n')


def import_nmap_scans(nmap_xml_files, output_dir):
    """ Import nmap XML to the scan directory. """
    log("Importing %s ..." % nmap_xml_files, 'info')
    for xml_file in nmap_xml_files:
        if not os.path.exists(xml_file):
            log("File does not exist: %s" % xml_file, 'error')
            continue
    imported_xml = os.path.join(output_dir, 'imported.xml')
    merge_nmap_files(nmap_xml_files, imported_xml)
    update_nmap_summary([imported_xml])
    split_nmap_file(imported_xml, output_dir)
    log("Done importing into %s" % output_dir, 'info')


def get_host_list(nmap_xml=None):
    """ Extract hosts from nmap file. """
    if not nmap_xml:
        nmap_xml = os.path.join(config.OUTPUT_PATH, 'nmap_summary.xml')
    if not os.path.exists(nmap_xml):
        return []
    nmap_results = parse_nmap_xml(nmap_xml)
    return list(nmap_results.keys())


def get_logo():
    return r"""
 ____  _            _    _     _         _ 
| __ )| | __ _  ___| | _| |__ (_)_ __ __| |
|  _ \| |/ _` |/ __| |/ / '_ \| | '__/ _` |
| |_) | | (_| | (__|   <| |_) | | | | (_| |
|____/|_|\__,_|\___|_|\_\_.__/|_|_|  \__,_|
"""
