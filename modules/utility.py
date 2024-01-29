import asyncio
import ipaddress
import logging
import os
from itertools import chain

import aiohttp
import tldextract
from html_similarity import similarity

logger = logging.getLogger(__name__)
logging.basicConfig()


# Compare two HTML pages
async def compare_two_pages(original_page: str, check_page: str):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url=f"https://{original_page}", verify_ssl=False, timeout=3
                                   ) as original_resp:
                original_page_response = await original_resp.text()
            async with session.get(url=f"http://{check_page}", verify_ssl=False, timeout=3
                                   ) as check_resp:
                check_page_response = await check_resp.text()
            # Compare original_page with check_page and return list[tuple(IP,Similarity_Percentage),...]
            return (check_page, int(similarity(str(original_page_response), str(check_page_response), k=0.3) * 100))
        except aiohttp.ClientConnectorError as cce:
            logger.debug('Connection Error | ', str(cce))
            logger.info(f'Skipped | Error with {check_page}')
            return 0
        except asyncio.TimeoutError as te:
            return 0


# Read all WAF Ranges from 'PublicWAFs.txt'
async def parse_public_waf_ranges():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../data/PublicWAFs.txt'), 'r') as publicWAFs:
        next(publicWAFs)
        return [ip.strip() for ip in publicWAFs]


# Check every IP to filter out for WAF appearance
async def filter_out_waf_ips(ips_to_check: set):
    waf_ips_with_cidr = await parse_public_waf_ranges()
    clear_ips = set()
    all_waf_ips = set(chain.from_iterable(ipaddress.ip_network(waf_ip) for waf_ip in waf_ips_with_cidr))
    for ip_to_check in ips_to_check:
        if ipaddress.ip_address(ip_to_check) not in all_waf_ips:
            clear_ips.add(ip_to_check)
    return clear_ips


# Extract TLD from each domain
async def get_top_domains(domains: list[str]):
    domains = list(filter(None, domains))
    custom_tldextract = tldextract.TLDExtract(
        cache_dir=f'{os.path.normpath(os.path.join(os.path.realpath(__file__), '../../cache/tldextract-cache'))}')
    return [str(
        custom_tldextract.extract_str(domain).domain
        + '.'
        + custom_tldextract.extract_str(domain).suffix
    )
        for domain in domains]
