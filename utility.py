import os
import ipaddress
from itertools import chain
import tldextract
import asyncio
import aiohttp

from html_similarity import similarity, style_similarity, structural_similarity


# Compare two HTML pages
async def compare_two_pages(original_page: str, check_page: str):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url=f"http://{original_page}", verify_ssl=False
                                   ) as original_resp:
                original_page_response = await original_resp.text()
            async with session.get(url=f"http://{check_page}", verify_ssl=False
                                   ) as check_resp:
                check_page_response = await check_resp.text()
            # Compare original_page with check_page and return list[dict{IP:Similarity_Percentage}]
            return [{check_page, similarity(str(original_page_response), str(check_page_response), k=0.3) * 100}]
        except aiohttp.ClientConnectorError as e:
            # print('Connection Error | ', str(e))
            print(f'Skipped | Error with {check_page}')
            return 0


asyncio.run(compare_two_pages('142.251.39.46', '104.18.32.7'))


# Read all WAF Ranges from 'PublicWAFs.txt'
def parse_public_waf_ranges():
    with open("PublicWAFs.txt") as publicWAFs:
        next(publicWAFs)
        return [ip.strip() for ip in publicWAFs]


# Check every IP to filter out for WAF appearance
def filter_ips_from_waf(ips_to_check: list[str]):
    waf_ips_with_cidr = parse_public_waf_ranges()
    clear_ips = []
    all_waf_ips = set(chain.from_iterable(ipaddress.ip_network(waf_ip) for waf_ip in waf_ips_with_cidr))
    for ip_to_check in ips_to_check:
        if ipaddress.ip_address(ip_to_check) not in all_waf_ips:
            clear_ips.append(ip_to_check)
    return clear_ips


# Extract TLD from each domain
def get_top_domains(domains: list[str]):
    domains = list(filter(None, domains))
    custom_tldextract = tldextract.TLDExtract(cache_dir=f'{os.getcwd()}' + '/cache/tldextract-cache')
    return [str(
        custom_tldextract.extract_str(domain).domain
        + '.'
        + custom_tldextract.extract_str(domain).suffix
    )
        for domain in domains]
