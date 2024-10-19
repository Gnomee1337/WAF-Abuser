import datetime
import json
import logging
import os
import aiohttp
from itertools import chain
from bs4 import BeautifulSoup
from modules.utility import get_top_domains

logger = logging.getLogger(__name__)


async def dnsdumpster_scraping(domain: str):
    dnsdumpster_output = []
    CSRFtoken = ''
    # Verify that 'dnsdumpster_req_logs' directory exists
    if not os.path.isdir(os.path.normpath(
            os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/dnsdumpster_req_logs/')))):
        os.makedirs(
            os.path.normpath(
                os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/dnsdumpster_req_logs/'))))
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:
        # GET-Request for each domain to receive unique CSRFToken
        async with session.get('https://dnsdumpster.com') as resp:
            cookies = session.cookie_jar.filter_cookies('https://dnsdumpster.com')
            CSRFtoken = str(cookies.get('csrftoken')).split('Set-Cookie: csrftoken=')[1]
        # POST-Request for each domain
        async with session.post('https://dnsdumpster.com',
                                data={'csrfmiddlewaretoken': CSRFtoken,
                                      'targetip': domain,
                                      'user': 'free'},
                                headers={'Host': 'dnsdumpster.com',
                                         'Pragma': 'no-cache',
                                         'Cache-Control': 'no-cache',
                                         'Upgrade-Insecure-Requests': '1',
                                         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                                         'Origin': 'https://dnsdumpster.com',
                                         'Content-Type': 'application/x-www-form-urlencoded',
                                         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                                         'Referer': 'https://dnsdumpster.com/',
                                         'Accept-Language': 'en-US,en;q=0.9,nl;q=0.8',
                                         'Cookie': f'csrftoken={CSRFtoken}'}
                                ) as resp:
            response_text = await resp.text()
        # Write HTML-Response to file
        with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                f'../../cache/dnsdumpster_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_HTML.txt')),
                  'a') as post_request_file:
            post_request_file.write(response_text)
        soup = BeautifulSoup(response_text.encode('utf-8'), 'html.parser')
        rb = soup.find_all('td', {'class': 'col-md-4'})
        # Find all domains in HTML-Response
        for found_domain in rb:
            dnsdumpster_output.append(
                found_domain.text.replace('\n', '').split('HTTP')[0].replace('. ', '').lstrip('1234567890 ').rstrip(
                    '.'))
        # Write only domains to file
        with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                f'../../cache/dnsdumpster_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt')),
                  'a') as domains_only_file:
            domains_only_file.write(
                "\n".join(str(dnsdumpster_out_domain) for dnsdumpster_out_domain in dnsdumpster_output))
    return dnsdumpster_output


async def certspotter_scraping(domain: str):
    certspotter_output = set()
    # Verify that 'certspotter_req_logs' directory exists
    if not os.path.isdir(os.path.normpath(
            os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/certspotter_req_logs/')))):
        os.makedirs(
            os.path.normpath(
                os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/certspotter_req_logs/'))))
    async with aiohttp.ClientSession() as session:
        # Get-Request for each domain with JSON-Response
        async with session.get(f'https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names',
                               headers={'Accept': 'application/json'}
                               ) as resp:
            response_text = await resp.json(encoding='utf-8')
            # Write JSON-Response to file
            with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                    f'../../cache/certspotter_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json')),
                      'a') as json_request_file:
                json.dump(response_text, json_request_file, sort_keys=True, indent=4)
            # Get all domains from JSON-Response
            for dict_in_resp in response_text:
                for list_in_dict_resp in dict_in_resp['dns_names']:
                    certspotter_output.add(list_in_dict_resp.lstrip('*.'))
            # Write only domains to file and remove wildcards
            with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                    f'../../cache/certspotter_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt')),
                      'a') as domains_only_file:
                domains_only_file.write(
                    "\n".join(str(certspotter_out_domain) for certspotter_out_domain in certspotter_output))
    return list(certspotter_output)


async def hackertarget_scraping(domain: str):
    hackertarget_output = set()
    # Verify that 'hackertarget_req_logs' directory exists
    if not os.path.isdir(os.path.normpath(
            os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/hackertarget_req_logs/')))):
        os.makedirs(
            os.path.normpath(
                os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/hackertarget_req_logs/'))))
    async with aiohttp.ClientSession() as session:
        # Get-Request for each domain with TEXT-Response
        async with session.get(f'https://api.hackertarget.com/hostsearch/?q={domain}',
                               ) as resp:
            response_text = await resp.text(encoding='utf-8')
            if not response_text.find('API count exceeded'):
                print(
                    'SKIP HackerTarget | Daily Limit Exceeded. (Possible bypass: new IP or use hackertarget.com API Key)')
            else:
                # Write TEXT-Response to file
                with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                        f'../../cache/hackertarget_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_TEXT.txt')),
                          'a') as text_request_file:
                    text_request_file.write(str(response_text))
                # Get all domains from TEXT-Response
                for line in response_text.split():
                    hackertarget_output.add(line.split(sep=",")[0])
                # Write only domains to file
                with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                        f'../../cache/hackertarget_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt')),
                          'a') as domains_only_file:
                    domains_only_file.write(
                        "\n".join(str(hackertarget_out_domain) for hackertarget_out_domain in hackertarget_output))
    return list(hackertarget_output)


async def crtsh_scraping(domain: str):
    crtsh_output = list()
    # Verify that 'crtsh_req_logs' directory exists
    if not os.path.isdir(
            os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/crtsh_req_logs/')))):
        os.makedirs(
            os.path.normpath(os.path.dirname(os.path.join(os.path.realpath(__file__), '../../cache/crtsh_req_logs/'))))
    async with aiohttp.ClientSession() as session:
        # Get-Request for each domain with JSON-Response
        async with session.get(f'https://crt.sh/?q={domain}&output=json',
                               headers={'Accept': 'application/json'}
                               ) as resp:
            response_text = await resp.json(encoding='utf-8')
            # Write JSON-Response to file
            with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                    f'../../cache/crtsh_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json')
                                       ),
                      'a') as json_request_file:
                json.dump(response_text, json_request_file, sort_keys=True, indent=4)
            # Get all domains from JSON-Response
            for list_in_resp in response_text:
                crtsh_output.append(list_in_resp['name_value'].split('\n'))
            # Flatten list(dict(),list(),str,...) to set() for only unique values
            crtsh_output_flatten = set(chain.from_iterable(crtsh_output))
            # Filter out wildcard domains
            crtsh_output_flatten = {filter_domain for filter_domain in crtsh_output_flatten if
                                    str(filter_domain).find('*.')}
            # Write only domains to file
            with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                    f'../../cache/crtsh_req_logs/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt')),
                      'a') as domains_only_file:
                domains_only_file.write(
                    "\n".join(str(crtsh_out_domain) for crtsh_out_domain in crtsh_output_flatten))
    return list(crtsh_output_flatten)


async def subdomain_gathering(domains: set):
    all_domains_and_subdomains = set()
    for domain in domains:
        all_subdomains_set = set()
        # Find all possible subdomain/domain for each domain
        all_subdomains_set.update(await dnsdumpster_scraping(domain))
        all_subdomains_set.update(await certspotter_scraping(domain))
        all_subdomains_set.update(await hackertarget_scraping(domain))
        all_subdomains_set.update(await crtsh_scraping(domain))
        # Add own domain
        all_subdomains_set.add(domain)
        # Add TLD
        all_subdomains_set.update(await get_top_domains([domain]))
        if len(all_subdomains_set) == 0:
            continue
        else:
            # Write to file all possible subdomains for domain
            with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                    f'../../cache/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_subdomains.txt')),
                      'a') as all_subdomains:
                all_subdomains.write(
                    "\n".join(str(subdomain_in_all) for subdomain_in_all in sorted(all_subdomains_set)))
            # Add all subdomains to 'all_domains_and_subdomains'
            all_domains_and_subdomains.update(all_subdomains_set)
        # Clear set() for next domain gathering
        all_subdomains_set.clear()
    # Write to file combination of ALL domains/subdomains for every given domain as input
    with open(os.path.normpath(os.path.join(os.path.realpath(__file__),
                                            f'../../cache/ALL_DOMAINS_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.txt')),
              'a') as all_domains:
        all_domains.write(
            "\n".join(str(domain_in_all) for domain_in_all in sorted(all_domains_and_subdomains)))
    return sorted(all_domains_and_subdomains)
