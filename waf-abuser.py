#!/usr/bin/env python3
import argparse
import os
import datetime
import fileinput
import sys
import threading
import traceback
from colorama import Fore, init as colorama_init
from modules.ip_gathering import ip_gathering
from modules.subdomain_gathering import subdomain_gathering
from modules.utility import WAFUtils


class WAFAbuser:
    def __init__(self, logger_level=WAFUtils.logging.CRITICAL):
        self.logger = self.create_logger(logger_level)
        self.input_domains = set()
        self.similarity_rate = 70
        self.domains_only_flag = False

    @staticmethod
    def create_logger(logger_level):
        log_format = (
            '[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
            if logger_level == WAFUtils.logging.DEBUG
            else '{%(filename)s:%(lineno)d} | %(message)s'
        )
        WAFUtils.logging.basicConfig(
            stream=sys.stdout,
            format=log_format,
            encoding='utf-8',
            level=logger_level
        )
        return WAFUtils.logging.getLogger(__name__)

    @staticmethod
    async def print_banner():
        colorama_init()
        banner = f"""{Fore.MAGENTA}
        +-----------------------------+
        |╦ ╦╔═╗╔═╗  ╔═╗╔╗ ╦ ╦╔═╗╔═╗╦═╗|
        |║║║╠═╣╠╣   ╠═╣╠╩╗║ ║╚═╗║╣ ╠╦╝|
        |╚╩╝╩ ╩╚    ╩ ╩╚═╝╚═╝╚═╝╚═╝╩╚═|
        +-----------------------------+
        {Fore.RESET}"""
        print(banner)

    async def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='WAF-Abuser will search the history for unprotected IPs associated with given domains to bypass the WAF over a direct connection')
        required = parser.add_argument_group("Required arguments")
        optional = parser.add_argument_group("Optional arguments")
        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument('-d', '--domain', action='store', dest='input_domain', metavar='"domain"',
                                 help='Specify the domain for searches')
        input_group.add_argument('-f', '--file', action='store', dest='file_domains', metavar='FILE with domains',
                                 nargs='*', help='Specify the file with domains for searches')
        optional.add_argument('--similarity-rate', action='store', dest='similarity_rate', default=self.similarity_rate,
                              metavar='[0-100]',
                              help=f'Specify minimum passing percentage for page similarity. Default: {self.similarity_rate}')
        optional.add_argument('--domains-only', action='store_true', dest='domains_only',
                              help='Find only domains and subdomains')
        # Parse the arguments
        args = parser.parse_args()
        # Get similarity rate
        self.similarity_rate = args.similarity_rate
        # Get domain only flag
        self.domains_only_flag = args.domains_only
        # Get domain names from arguments
        if args.file_domains:
            self.input_domains.update(line.strip() for line in fileinput.input(files=args.file_domains))
        elif args.input_domain:
            self.input_domains.add(args.input_domain)
        else:
            raise ValueError("Improper -d/-f argument")

    async def gather_subdomains(self):
        print("1. Gathering subdomains")
        find_subdomains = await subdomain_gathering(self.input_domains)
        self.logger.debug(f"Subdomains gathered: {find_subdomains}")
        return find_subdomains

    async def gather_ips(self, subdomains):
        print("2. Gathering IPs")
        find_ips = await ip_gathering(subdomains)
        self.logger.debug(find_ips)
        return find_ips

    async def filter_waf_ips(self, ips):
        print("3. Filtering out WAF IPs")
        filtered_out_ips = await WAFUtils.filter_out_waf_ips(ips)
        self.logger.debug(filtered_out_ips)
        return filtered_out_ips

    async def compare_ips_with_domains(self, filtered_out_ips):
        print("4. Comparing found IPs with original domain")
        # Compare input domain content with filtered out IPs content
        similarity_output = set()
        for input_domain in self.input_domains:
            current_domain_content = await WAFUtils.get_page_content(input_domain)
            if current_domain_content == 0:
                continue  # Skip if there was an error fetching the domain content
            await self.compare_with_filtered_ips(current_domain_content, filtered_out_ips, similarity_output)
        return similarity_output

    async def compare_with_filtered_ips(self, current_domain_content, filtered_out_ips, similarity_output):
        for filtered_ip in filtered_out_ips:
            compare_result = await WAFUtils.compare_two_pages(original_page=current_domain_content,
                                                              check_page=filtered_ip)
            # Add if similarity rate > than specified (Default 70%)
            if compare_result != 0 and compare_result[1] > int(self.similarity_rate):
                similarity_output.add(compare_result)

    async def output_results(self, similarity_output):
        if not similarity_output:
            print(f"5. {Fore.YELLOW}Found 0 pages with similarity > {self.similarity_rate}%{Fore.RESET}")
            return
        self.print_similarity_header()
        self.print_similarity_details(similarity_output)
        await self.save_results_to_file(similarity_output)

    def print_similarity_header(self):
        print(f"5. {Fore.GREEN}Found possible IPs:")

    def print_similarity_details(self, similarity_output):
        row_format = "{:>15}" * (len(similarity_output) + 1)
        print(row_format.format("IP", "Similarity"))
        for ip_and_rate in similarity_output:
            print(row_format.format(ip_and_rate[0], f"{ip_and_rate[1]})%"))

    async def save_results_to_file(self, similarity_output):
        # Verify that 'output' directory exists
        output_dir = os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), '../output/')))
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir,
                                   f'possible_WAF_bypass_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.txt')
        with open(output_file, 'a') as waf_bypass_to_file:
            lines = [
                f"{ip_and_rate[0]:>15} {ip_and_rate[1]}%" for ip_and_rate in similarity_output
            ]
            waf_bypass_to_file.write("\n".join(lines) + "\n")

    async def run(self):
        await self.print_banner()
        await self.parse_arguments()
        subdomains = await self.gather_subdomains()
        if self.domains_only_flag:
            await self.display_subdomains(subdomains)
            return
        ips = await self.gather_ips(subdomains)
        filtered_out_ips = await self.filter_waf_ips(ips)
        if not filtered_out_ips:
            print(f"{Fore.GREEN}Found 0 possible non-WAF IPs")
            return
        similarity_output = await self.compare_ips_with_domains(filtered_out_ips)
        await self.output_results(similarity_output)

    async def display_subdomains(self, subdomains):
        print(f"{Fore.GREEN}Found {len(subdomains)} domains/subdomains:{Fore.RESET}")
        for domain in subdomains:
            print(domain)
        print(f"File output: {os.path.normpath(os.path.join(os.path.realpath(__file__), '../cache/'))}")


if __name__ == '__main__':
    scanner = WAFAbuser()
    try:
        WAFUtils.asyncio.run(scanner.run())
    except (KeyboardInterrupt, SystemExit):
        pass  # Graceful exit on user interrupt or system exit
    except Exception:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        # Exit the program gracefully based on active threads
        exit_code = getattr(os, "_exitcode", 0)
        if threading.active_count() > 1:
            os._exit(exit_code)
        else:
            sys.exit(exit_code)
