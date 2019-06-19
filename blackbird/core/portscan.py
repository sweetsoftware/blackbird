import multiprocessing
import os

from blackbird import utils
from blackbird import config


def _port_scan(target, output_dir):
    output_path = os.path.join(output_dir, target)
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    cmd = 'nmap -v -sV -sT -Pn -T4 -n --open -oA %s %s' % (output_path + '/ports-tcp', target)
    if not config.FAST_SCAN:
        cmd += " -p-"
    utils.run_cmd(cmd)
    cmd = 'nmap -v -sV --defeat-icmp-ratelimit -Pn -sU -T4 -n --open -oA %s %s' % (output_path + '/ports-udp', target)
    if not config.FAST_SCAN:
        cmd += " -F"
    else:
        cmd += " --top-ports 20"
    utils.run_cmd(cmd)


def run(output_dir):
    jobs = []

    sweep_file = os.path.join(output_dir, 'sweep.xml')
    if not os.path.exists(sweep_file):
        utils.log("Could not parse host list... have you performed a ping sweep first (--sweep) or specified the --no-sweep flag ? ", 'info')
        exit(1)
    for target in utils.get_host_list(sweep_file):
        scan_p = (target, output_dir)
        jobs.append(scan_p)

    pool = multiprocessing.Pool(10)
    pool.starmap(_port_scan, jobs)
    pool.close()
    pool.join()
