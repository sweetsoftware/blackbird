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

from blackbird.core import config
from blackbird.core import log
from blackbird.core.exceptions import BlackBirdError


async def run_cmd(cmdline, timeout=config.CMD_TIMEOUT, print_output=True, wdir=None, outfile=None):
    """ Run a command asynchronously and return output.
    Enforce a timeout and max conccurent processes run by the program.
    """
    while len(config.RUNNING_PROCS) >= config.MAX_TASKS:
        # Too many tasks running, sleeping for some time
        await asyncio.sleep(1)
    config.RUNNING_PROCS.append(cmdline)
    log.info("Running : {}".format(cmdline))
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
                log.info("Output for : {}".format(cmdline))
                log.log(output)
            config.RUNNING_PROCS.remove(cmdline)
            if config.RUNNING_PROCS:
                log.info("%s tasks running ..." % len(config.RUNNING_PROCS))
            if outfile:    
                with open(outfile, 'w') as out:
                    out.write(output)
            return output
        else:
            config.RUNNING_PROCS.remove(cmdline)
            return "Dry run."
    except asyncio.TimeoutError:
        log.warn("Command execution timed out : {}".format(cmdline))
        return ""
    except Exception as exc:
        if cmdline in config.RUNNING_PROCS:
            config.RUNNING_PROCS.remove(cmdline)
        log.warn("Command execution failed : {}\n{}".format(cmdline, exc))
        return ""


def parse_nmap_xml(filename):
    """ Read nmap XML file and returns data as a dict. """
    host_info = dict()
    if not os.path.exists(filename):
        raise BlackBirdError("%s nmap XML not found" % filename)
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
