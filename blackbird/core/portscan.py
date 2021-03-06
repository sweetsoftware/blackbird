import multiprocessing
import os
import shutil
import glob

from blackbird import utils
from blackbird import config


def _port_scan(target, output_dir):
    output_path = os.path.join(output_dir, target)
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    # TCP scan
    cmd = 'nmap -v -sV -sT -Pn --open -oX %s %s' % (output_path + '/ports-tcp.xml', target)
    if config.FULL_SCAN:
        cmd += " -p- -T4"
    else:
        cmd += " -T5"
    utils.run_cmd(cmd)
    # UDP scan
    cmd = 'nmap -v -n -sV --defeat-icmp-ratelimit -Pn -sU -T4 --open -oX %s %s' % (output_path + '/ports-udp.xml', target)
    if config.FULL_SCAN:
        cmd += " "
    else:
        cmd += " --top-ports 200"
    utils.run_cmd(cmd)
    tcp_scan = os.path.join(output_path, "ports-tcp.xml")
    udp_scan = os.path.join(output_path, "ports-udp.xml")
    port_scan_file = os.path.join(output_path, "port-scan.xml")
    utils.merge_nmap_files([tcp_scan, udp_scan], port_scan_file)
    os.remove(tcp_scan)
    os.remove(udp_scan)
    results = utils.parse_nmap_xml(port_scan_file)
    if not results:
        utils.log("No open ports on %s, deleting directory..." % target, "warning")
        shutil.rmtree(output_path)


def run(output_dir):
    jobs = []
    utils.log('Initiating port scan on targets','info')
    sweep_file = os.path.join(output_dir, 'sweep.xml')
    if not os.path.exists(sweep_file):
        utils.log("Could not parse host list... have you performed a ping sweep first (--sweep) or specified the --no-sweep flag ? ", 'error')
        exit(1)
    for target in utils.get_host_list(sweep_file):
        scan_p = (target, output_dir)
        jobs.append(scan_p)

    pool = multiprocessing.Pool(10)
    pool.starmap(_port_scan, jobs)
    pool.close()
    pool.join()
    scan_files = glob.glob(os.path.join(output_dir, '*', '*.xml'))
    utils.update_nmap_summary(scan_files)
