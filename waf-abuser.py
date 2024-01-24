#!/usr/bin/env python3
import argparse
import ipaddress
import logging
import os
import sys
import threading
import traceback
from itertools import chain
import tldextract
from utility import *


# from subdomain_gathering import subdomain_gathering


def create_logger(name: str, logger_level: logging):
    if logger_level is logging.DEBUG:
        logging.basicConfig(stream=sys.stdout,
                            format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
                            encoding='utf-8', level=logger_level)
    else:
        logging.basicConfig(stream=sys.stdout, format='{%(filename)s:%(lineno)d} | %(message)s', encoding='utf-8',
                            level=logger_level)
    logger = logging.getLogger(name)
    return logger


def arguments():
    parser = argparse.ArgumentParser(description='CHANGE DESC')
    required = parser.add_argument_group("Required arguments")
    required.add_argument('-d', '--domain', action='store', dest='domain', help='Specify FQDN/Domain for search',
                          required=True)
    args = parser.parse_args()
    domain = args.domain


def main():
    arguments()
    logger = create_logger("main-logger", logging.DEBUG)
    get_top_domains(['google.com', 'https://facebook.com', 'http://forums.bbc.co.uk', 'twitter.com:443', '', ' ', ''])
    # is_ip_in_publicWAF(['197.234.240.1','198.234.240.1','197.234.240.22','149.126.72.1','104.32.0.0'])
    # for i in ip_ranges:
    #    logger.info(i)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
