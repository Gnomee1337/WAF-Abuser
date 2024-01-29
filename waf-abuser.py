#!/usr/bin/env python3
import argparse
import datetime
import fileinput
import sys
import threading
import traceback
import os

from colorama import Fore
from colorama import init as colorama_init

from modules.ip_gathering import ip_gathering
from modules.subdomain_gathering import subdomain_gathering
from modules.utility import *


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
    logger = await create_logger(__name__, logging.CRITICAL)
    colorama_init()
    # Get domain name from arguments
    input_domains = set()
    similarity_rate = args.similarity_rate
    if args.file_domains:
        for line in fileinput.input(files=args.file_domains):
            input_domains.add(line.strip())
    elif args.input_domain:
        input_domains.add(args.input_domain)
    else:
        raise ValueError("Improper -d/-f argument")
    # Gathering subdomains for input domains
    print("1. Gathering subdomains")
    find_subdomains = set()
    find_subdomains.update(await subdomain_gathering(input_domains))
    logger.debug(find_subdomains)
    # Gathering IPs for subdomains
    print("2. Gathering IPs")
    find_ips = set()
    find_ips.update(await ip_gathering(find_subdomains))
    logger.debug(find_ips)
    # Filtering out WAF-IPs from gathered IPs
    print("3. Filtering out WAF IPs")
    filtered_out_ips = set()
    filtered_out_ips.update(await filter_out_waf_ips(find_ips))
    logger.debug(filtered_out_ips)
    # All IPs were from WAF-Ranges
    if len(filtered_out_ips) == 0:
        print(f"{Fore.GREEN}Found 0 possible non-WAF IPs")
        return 0
    else:
        print("4. Comparing found IPs with original domain")
        # Compare input domain content with filtered out IPs content
        similarity_output = set()
        for input_domain in input_domains:
            for filtered_ip in filtered_out_ips:
                compare_result = await compare_two_pages(original_page=input_domain, check_page=filtered_ip)
                # Possible connection error/unavailable page
                if compare_result == 0:
                    continue
                # Add if similarity rate > than specified (Default 70%)
                elif compare_result[1] > int(similarity_rate):
                    similarity_output.add(compare_result)
                else:
                    continue
    # Output final results
    if len(similarity_output) == 0:
        print(
            f"5. {Fore.YELLOW}Found 0 pages with similarity > {str(similarity_rate)}%.{Fore.RESET}"
            "\nYou can reduce the similarity percentage [--similarity_rate 70]"
            "\nDefault similarity value: 70")
        return 0
    else:
        print(f"5. {Fore.GREEN}Found possible IPs:")
        row_format = "{:>15}" * (len(similarity_output) + 1)
        print(row_format.format("IP", "Similarity"))
        for ip_and_rate in similarity_output:
            print(row_format.format(ip_and_rate[0], str(ip_and_rate[1]) + '%'))
        # Verify that 'output' directory exists
        if not os.path.isdir(os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), '../output/')))):
            os.makedirs(os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), '../output/'))))
        with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                f'../output/possible_WAF_bypass_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.txt')),
                  'a') as waf_bypass_to_file:
            waf_bypass_to_file.write(
                "\n".join(row_format.format(ip_and_rate[0], str(ip_and_rate[1]) + '%') for ip_and_rate in
                          similarity_output))


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
