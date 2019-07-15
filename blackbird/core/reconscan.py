import multiprocessing
import os
import signal
import psutil
import time
import termcolor
import select
import sys
import datetime

from blackbird import utils
from blackbird import config
from blackbird import modules


remaining_jobs = []
running_jobs = []


class ReconProcess(multiprocessing.Process):
    def __init__(self, toExecute):
        multiprocessing.Process.__init__(self)
        self.toExecute = toExecute

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.toExecute()

    def to_str(self):
        current_proc = psutil.Process(self.pid)
        out = ""
        creation_time = datetime.datetime.fromtimestamp(current_proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
        for child in current_proc.children():
            out += "PID=" + str(child.pid) + "\nCREATED=" + creation_time + "\nCMD=" + str(child.cmdline())
        return out

    def suspend(self):
        current_proc = psutil.Process(self.pid)
        for child in current_proc.children(recursive=True):
            child.suspend()
        current_proc.suspend()

    def resume(self):
        current_proc = psutil.Process(self.pid)
        for child in current_proc.children(recursive=True):
            child.resume()
        current_proc.resume()

    def stop(self):
        current_proc = psutil.Process(self.pid)
        for child in current_proc.children(recursive=True):
            child.kill()
        current_proc.kill()


def get_target_modules(target, output_dir):
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
                jobs.append(module_instance)
    return jobs


def interrupt_menu(*args):
    for i in running_jobs:
        i.suspend()
    utils.log("Invoking interactive menu...", "info")
    time.sleep(1)
    print(termcolor.colored("*" * 80, 'green'))
    print("Running processes:")
    for i in range(len(running_jobs)):
        job = running_jobs[i]
        print("\n"+ termcolor.colored(i, 'green') + " - %s" % job.to_str())
    print(termcolor.colored("*" * 80, 'green'))

    to_kill = input("Choose processes to kill (comma separated) (-1 to kill all): ")
    to_kill = to_kill.split(',')

    for item in to_kill:
        try:
            item = int(item)
            if item not in range(len(running_jobs)) and item != -1:
                utils.log("Invalid choice")
                break
        except:
            utils.log("Invalid choice")
            break
    # No error in input, proceed to kill processes
    else:
        killed_procs = []
        for choice in to_kill:
            choice = int(choice)
            if choice >= 0:
                proc_to_kill = running_jobs[choice]
                utils.log("Killing pid %s" % proc_to_kill.pid)
                proc_to_kill.stop()
                killed_procs.append(proc_to_kill)
            elif choice == -1:
                utils.log("Killing all remaining jobs")
                for i in running_jobs:
                    i.stop()
                global remaining_jobs
                remaining_jobs = []
        for proc in killed_procs:
            running_jobs.remove(proc)
    utils.log("Resuming jobs...")
    for i in running_jobs:
        i.resume()

def get_user_input():
    while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        line = sys.stdin.readline()
        if line:
            return line
    else:
        return False


def run(output_dir):
    sweep_file = os.path.join(output_dir, 'sweep.xml')
    if not os.path.exists(sweep_file):
        utils.log("Could not parse host list... have you performed a ping sweep first (--sweep) or specified the --no-sweep flag ? ", 'info')
        exit(1)

    for target in utils.get_host_list(sweep_file):
        target_modules = get_target_modules(target, output_dir)
        if target_modules:
            for module in target_modules:
                if config.ENUM:
                    proc = ReconProcess(module.enum)
                    remaining_jobs.append(proc)
            for module in target_modules:
                if config.BRUTE:
                    proc = ReconProcess(module.brute)
                    remaining_jobs.append(proc)

    while remaining_jobs or running_jobs:
        cmd = get_user_input()
        if cmd:
            if cmd.strip() == 'b':
                interrupt_menu()
                continue
        for job in running_jobs:
            if not job.is_alive():
                running_jobs.remove(job)
                continue
        if len(running_jobs) <= config.MAX_JOBS and remaining_jobs:
            next_job = remaining_jobs[0]
            running_jobs.append(next_job)
            next_job.start()
            remaining_jobs.remove(next_job)
            utils.log('Remaining jobs: %s' % remaining_jobs, 'info')
            continue
    utils.log('Waiting remaining jobs...', 'info')
    for job in running_jobs:
        job.join()
