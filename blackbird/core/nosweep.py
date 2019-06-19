import os

from blackbird import utils


def run(targets, output_dir):
    utils.log("Importing target list", "info")
    utils.run_cmd("nmap -n -T4 -v -sL -oA %s %s" % (os.path.join(output_dir, 'sweep'), targets))
