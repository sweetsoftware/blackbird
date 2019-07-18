from blackbird import utils


def run(target_file, output_dir):
    utils.log("Performing ping sweep on targets ...", "info")
    cmd = "nmap -v -n --open -sn -iL %s -oA %s/sweep" % (target_file, output_dir)
    utils.run_cmd(cmd)
