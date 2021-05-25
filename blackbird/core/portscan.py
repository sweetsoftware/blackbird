import multiprocessing
import os
import shutil
import glob
import asyncio

from blackbird import utils
from blackbird import config


async def _port_scan(target, output_dir):
    output_path = os.path.join(output_dir, target)
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    # TCP scan
    cmd = 'nmap -Pn -n -sT -sV -T4 --open -oX %s %s' % (output_path + '/ports-tcp.xml', target)
    if config.PORTS:
        cmd += " -p %s" % config.PORTS
    elif config.FULL_SCAN:
        cmd += " -p-"
    await utils.run_cmd(cmd)
    # UDP scan
    if config.UDP_SCAN:
        cmd = 'nmap -Pn -n -sU -sV --min-rate 500 -T4 --open --defeat-icmp-ratelimit -oX %s %s' % (output_path + '/ports-udp.xml', target)
        if config.PORTS:
            cmd += " -p %s" % config.PORTS
        elif config.FULL_SCAN:
            cmd += " -p-"
        await utils.run_cmd(cmd)
    tcp_scan = os.path.join(output_path, "ports-tcp.xml")
    udp_scan = os.path.join(output_path, "ports-udp.xml")
    port_scan_file = os.path.join(output_path, "port-scan.xml")
    if os.path.exists(udp_scan):
        utils.merge_nmap_files([tcp_scan, udp_scan], port_scan_file)
        os.remove(udp_scan)
    else:
        shutil.copy(tcp_scan, port_scan_file)
    os.remove(tcp_scan)
    results = utils.parse_nmap_xml(port_scan_file)
    if not results:
        utils.log("No open ports on %s, deleting directory..." % target, "warning")
        shutil.rmtree(output_path)


async def run(targets):
    utils.log('Initiating port scan on targets: {}'.format(targets),'info')
    await asyncio.gather(*(_port_scan(target, config.OUTPUT_PATH) for target in targets))
    scan_files = glob.glob(os.path.join(config.OUTPUT_PATH, '*', '*.xml'))
    utils.update_nmap_summary(scan_files)
