#!/usr/bin/env python3

import os

from blackbird import config

os.system('pip3 install -r ' + os.path.join(config.INSTALL_DIR, 'requirements.txt'))

from blackbird import utils

for module in utils.get_module_list():
    cmd = os.path.join(config.INSTALL_DIR, 'blackbird/modules/%s/setup.sh' % module)
    if os.path.exists(cmd):
        os.system(cmd)

os.system('ln -sf ' + os.path.join(config.INSTALL_DIR, 'blackbird.py') + ' /usr/local/bin/blackbird')

