#!/usr/bin/env python3
import argparse
import fileinput
import ipaddress
import logging
import os
import sys
import threading
import traceback
from itertools import chain
import tldextract
from utility import *
from subdomain_gathering import subdomain_gathering
from ip_gathering import ip_gathering


async def create_logger(name: str, logger_level: logging):
    if logger_level is logging.DEBUG:
        logging.basicConfig(stream=sys.stdout,
                            format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
                            encoding='utf-8', level=logger_level)
    else:
        logging.basicConfig(stream=sys.stdout, format='{%(filename)s:%(lineno)d} | %(message)s', encoding='utf-8',
                            level=logger_level)
    logger = logging.getLogger(name)
    return logger


'''CHANGE ARGS DESCRIPTION'''


async def arguments():
    parser = argparse.ArgumentParser(description='CHANGE DESC')
    required = parser.add_argument_group("Required arguments")
    optional = parser.add_argument_group("Optional arguments")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-d', '--domain', action='store', dest='input_domain',
                             help='Specify FQDN/Domain for search',
                             )
    input_group.add_argument('-f', '--file', action='store', dest='file_domains', metavar='FILE', nargs='*',
                             help='Specify file with Domains for search',
                             )
    optional.add_argument('--similarity_rate', action='store', dest='similarity_rate', default=70,
                          help='Specify minimum passing percentage of page similarity (Default 70%)',
                          )
    return parser.parse_args()


async def main():
    args = await arguments()
    logger = await create_logger("main-logger", logging.DEBUG)
    # Get domain name from arguments
    input_domains = set()
    similarity_rate = args.similarity_rate
    if args.file_domains:
        for line in fileinput.input(files=args.file_domains):
            input_domains.add(line.strip())
    elif args.input_domain:
        input_domains.add(args.input_domain)
    else:
        return 1
    # Gathering subdomains for input domains
    print("Gathering subdomains")
    find_subdomains = set()
    find_subdomains.update(await subdomain_gathering(input_domains))
    logger.debug(find_subdomains)
    # Gathering IPs for subdomains
    print("Gathering IPs")
    find_ips = set()
    find_ips.update(await ip_gathering(find_subdomains))
    logger.debug(find_ips)
    # Filtering out WAF-IPs from gathered IPs
    print("Filtering out WAF-IPs")
    filtered_out_ips = set()
    filtered_out_ips.update(await filter_out_waf_ips(find_ips))
    logger.debug(filtered_out_ips)
    # Compare input domain content with filtered out IPs content
    similarity_output = set()
    for input_domain in input_domains:
        for filtered_ip in filtered_out_ips:
            compare_result = await compare_two_pages(original_page=input_domain, check_page=filtered_ip)
            print(f'MAIN Compare_result: {compare_result}')
            if compare_result == 0:
                continue
            elif compare_result[1] > similarity_rate:
                similarity_output.add(compare_result)
            else:
                continue
    # Output final
    print("FINAL OUTPUT")
    for ip_and_rate in similarity_output:
        print(f'{ip_and_rate[0]} | {ip_and_rate[1]}%')

    # get_top_domains(['google.com', 'https://facebook.com', 'http://forums.bbc.co.uk', 'twitter.com:443', '', ' ', ''])
    # is_ip_in_publicWAF(['197.234.240.1','198.234.240.1','197.234.240.22','149.126.72.1','104.32.0.0'])
    # for i in ip_ranges:
    #    logger.info(i)


if __name__ == '__main__':
    try:
        asyncio.run(main())
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
