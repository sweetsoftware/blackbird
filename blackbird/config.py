import os


CUSTOM_USER_LIST = ""
CUSTOM_PASS_LIST = ""
CUSTOM_USERPASS_LIST = ""

NO_PING = False
SCAN = False
FULL_SCAN = False
PORTS = None

OUTPUT_PATH = ""
MODULES = set()

ONLY_CUSTOM_BRUTE = False
DRY_RUN = False

INSTALL_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
MAX_TASKS = 50
SHOW_LOGO = True
