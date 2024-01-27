import asyncio
import logging
import sys

import aiohttp
import datetime
import os
from bs4 import BeautifulSoup

import re


async def ip_history_viewdnsinfo(domain: str):
    viewdnsinfo_ips_output = set()
    # Verify that 'viewdnsinfo_req_logs' directory exists
    if not os.path.isdir(os.getcwd() + '/cache/viewdnsinfo_req_logs'):
        os.mkdir(os.getcwd() + '/cache/viewdnsinfo_req_logs')
    async with aiohttp.ClientSession() as session:
        # GET-Request for each domain
        async with session.get(f'https://viewdns.info/iphistory/?domain={domain}'
                               ) as resp:
            response_text = await resp.text()
            # Write HTML-Response to file
            with open(os.path.join(os.getcwd() + '/cache/viewdnsinfo_req_logs',
                                   f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_HTML.txt'),
                      'a') as get_request_file:
                get_request_file.write(response_text)
            soup = BeautifulSoup(response_text.encode('utf-8'), 'html.parser')
            rb = soup.find_all('table', {'border': '1'})
            # Find all IPs in HTML-Response
            ip_pattern = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            viewdnsinfo_ips_output.update(ip_pattern.findall(str(rb)))
            # Write only IPs to file
            with open(os.path.join(os.getcwd() + '/cache/viewdnsinfo_req_logs',
                                   f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_ips.txt'),
                      'a') as domains_only_file:
                domains_only_file.write(
                    "\n".join(str(viewdnsinfo_out_ips) for viewdnsinfo_out_ips in viewdnsinfo_ips_output))
    return list(viewdnsinfo_ips_output)

async def ip_gathering(domains: list[str]):
    all_ips = set()
    for domain in domains:
        all_domain_ips = set()
        all_domain_ips.update(await ip_history_viewdnsinfo(domain))
        # Write to file all possible ips for domain
        with open(os.path.join(os.getcwd() + '/cache',
                               f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_IPs.txt'),
                  'a') as all_subdomains_ips_file:
            all_subdomains_ips_file.write(
                "\n".join(str(ip_in_ips_for_domain) for ip_in_ips_for_domain in sorted(all_domain_ips)))
        # Add all ips to 'all_ips'
        all_ips.update(all_domain_ips)
        # Clear set() for next ips gathering
        all_domain_ips.clear()
    # Write to file combination of ALL ips for every given domain as input
    with open(os.path.join(os.getcwd() + '/cache',
                           f'ALL_DOMAINS_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_IPs.txt'),
              'a') as ips_for_all_domains:
        ips_for_all_domains.write(
            "\n".join(str(ip_in_all) for ip_in_all in sorted(all_ips)))
    return sorted(all_ips)

asyncio.run(ip_gathering(['cbre.com']))
