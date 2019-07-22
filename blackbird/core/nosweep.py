import os

from blackbird import utils


def run(target_file, output_dir):
    utils.log("Importing all targets as alive", "info")
    utils.run_cmd("nmap -n -T4 -v -sL -oA %s -iL %s" % (os.path.join(output_dir, 'sweep'), target_file))
