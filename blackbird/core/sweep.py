from blackbird import utils


def run(target, output_dir):
    utils.log("Performing ping sweep on target %s" % target, "info")
    cmd = "nmap -v -n --open -sn %s -oA %s/sweep" % (target, output_dir)
    utils.run_cmd(cmd)
