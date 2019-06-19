#!/usr/bin/env python3

import os

from blackbird import utils


for module in utils.get_module_list():
    os.system('./blackbird/modules/%s/setup.sh' % module)

os.system('pip3 install -r requirements.txt')
