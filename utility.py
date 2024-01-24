import os
import ipaddress
from itertools import chain
import tldextract


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
