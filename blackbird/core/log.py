import logging
logging.basicConfig(format='%(message)s',level=logging.INFO)

import termcolor

from blackbird.core import config


# Output message to the logs
def log(log_str, log_type=''):
    if config.QUIET and log_type in ['info', 'warning']:
        return
    if log_type == 'info':
        logging.info(termcolor.colored('[I] ' + log_str, 'green'))
    elif log_type == 'error':
        logging.critical(termcolor.colored('[E] ' + log_str, 'red'))
    elif log_type == 'warning':
        logging.warning(termcolor.colored('[W] ' + log_str, 'yellow'))
    else:
        logging.info(log_str)


def info(log_str):
    log(log_str, 'info')


def warn(log_str):
    log(log_str, 'warning')


def error(log_str):
    log(log_str, 'error')
