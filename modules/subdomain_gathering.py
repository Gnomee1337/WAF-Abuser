import asyncio
import datetime
import json
import os
import aiofiles
import aiohttp
from itertools import chain
from bs4 import BeautifulSoup
from abc import ABC, abstractmethod

from modules.utility import WAFUtils


class BaseScraper(ABC):
    """Abstract base class for all scrapers."""

    def __init__(self, domain: str):
        self.domain = domain
        self.cache_dir = os.path.normpath(os.path.join(os.path.realpath(__file__), '../../cache'))
        os.makedirs(self.cache_dir, exist_ok=True)

    @abstractmethod
    async def scrape(self):
        """Method to perform the actual scraping logic, to be implemented by subclasses."""
        pass

    async def _write_to_file(self, content: str, file_name: str):
        """Asynchronously write content to a file using aiofiles."""
        file_path = os.path.join(self.cache_dir, file_name)
        async with aiofiles.open(file_path, 'a') as file:
            await file.write(content)


class JsonScraper(BaseScraper):
    """Abstract class for scrapers that expect JSON responses."""

    async def fetch_json(self, url: str):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={'Accept': 'application/json'}) as resp:
                return await resp.json(encoding='utf-8')


class CrtShScraper(JsonScraper):
    """Scraper for crt.sh"""

    def __init__(self, domain: str):
        super().__init__(domain)
        self.log_dir = os.path.join(self.cache_dir, 'crtsh_req_logs')
        os.makedirs(self.log_dir, exist_ok=True)

    async def scrape(self):
        """Main scraping method for crt.sh"""
        crtsh_output = []
        # Fetch JSON data from crt.sh
        response_json = await self._fetch_crtsh_data()
        # Write the JSON response to a file
        await self._write_json_response(response_json)
        # Extract and filter domains from the response
        crtsh_output_filtered = self._extract_and_filter_domains(response_json)
        # Write the filtered domains to a file
        await self._write_domains_to_file(crtsh_output_filtered)
        return list(crtsh_output_filtered)

    async def _fetch_crtsh_data(self):
        """Fetch JSON data from crt.sh"""
        url = f'https://crt.sh/?q={self.domain}&output=json'
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return await resp.json()

    async def _write_json_response(self, response_json):
        """Write the raw JSON response to a file"""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json'
        )
        async with aiofiles.open(file_path, 'w') as json_file:
            await json_file.write(json.dumps(response_json, sort_keys=True, indent=4))

    def _extract_and_filter_domains(self, response_json):
        """Extract and filter domains from the JSON response"""
        crtsh_output = [
            record['name_value'].split('\n') for record in response_json
        ]
        # Flatten list and filter out wildcard domains
        crtsh_output_flatten = set(chain.from_iterable(crtsh_output))
        crtsh_output_filtered = {domain for domain in crtsh_output_flatten if not domain.startswith('*.')}
        return crtsh_output_filtered

    async def _write_domains_to_file(self, crtsh_output_filtered):
        """Write the filtered domains to a file"""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt'
        )
        async with aiofiles.open(file_path, 'w') as domains_file:
            await domains_file.write("\n".join(sorted(crtsh_output_filtered)))


class DnsDumpsterScraper(BaseScraper):
    """Scraper for DnsDumpster.com"""

    DNSDUMPSTER_URL = 'https://dnsdumpster.com'

    def __init__(self, domain: str):
        super().__init__(domain)
        self.log_dir = os.path.join(self.cache_dir, 'dnsdumpster_req_logs')
        os.makedirs(self.log_dir, exist_ok=True)

    async def scrape(self):
        csrf_token = await self._get_csrf_token()
        # POST request to dnsdumpster.com with CSRF token and domain
        response_text = await self._post_domain_data(csrf_token)
        # Write the full HTML response to a file
        await self._write_html_response(response_text)
        # Parse HTML response and extract domains
        dnsdumpster_output = self._extract_domains(response_text)
        # Write extracted domains to a file
        await self._write_domains_to_file(dnsdumpster_output)
        return dnsdumpster_output

    async def _get_csrf_token(self):
        """Get CSRF token from dnsdumpster.com."""
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:
            async with session.get(self.DNSDUMPSTER_URL) as response:
                cookies = session.cookie_jar.filter_cookies(self.DNSDUMPSTER_URL)
                csrf_token = str(cookies.get('csrftoken')).split('Set-Cookie: csrftoken=')[1]
        return csrf_token

    async def _post_domain_data(self, csrf_token: str):
        """Send POST request to dnsdumpster.com with domain data."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                    self.DNSDUMPSTER_URL,
                    data={
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': self.domain,
                        'user': 'free'
                    },
                    headers={
                        'Host': 'dnsdumpster.com',
                        'Pragma': 'no-cache',
                        'Cache-Control': 'no-cache',
                        'Upgrade-Insecure-Requests': '1',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
                        'Origin': self.DNSDUMPSTER_URL,
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                        'Referer': self.DNSDUMPSTER_URL,
                        'Accept-Language': 'en-US,en;q=0.9,nl;q=0.8',
                        'Cookie': f'csrftoken={csrf_token}'
                    }
            ) as resp:
                return await resp.text()

    def _extract_domains(self, response_text: str):
        """Extract domain names from the HTML response using BeautifulSoup."""
        soup = BeautifulSoup(response_text, 'html.parser')
        rb = soup.find_all('td', {'class': 'col-md-4'})
        domains = [
            found_domain.text.replace('\n', '').split('HTTP')[0].replace('. ', '').lstrip('1234567890 ').rstrip('.')
            for found_domain in rb
        ]
        return domains

    async def _write_html_response(self, response_text: str):
        """Write HTML response to a file asynchronously."""
        file_path = os.path.join(self.log_dir,
                                 f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_HTML.txt')
        async with aiofiles.open(file_path, 'w') as post_request_file:
            await post_request_file.write(response_text)

    async def _write_domains_to_file(self, dnsdumpster_output):
        """Write only the extracted domains to a file asynchronously."""
        file_path = os.path.join(self.log_dir,
                                 f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt')
        async with aiofiles.open(file_path, 'w') as domains_only_file:
            await domains_only_file.write("\n".join(sorted(dnsdumpster_output)))


class CertSpotterScraper(BaseScraper):
    """Scraper for CertSpotter API."""

    def __init__(self, domain: str):
        super().__init__(domain)
        self.log_dir = os.path.join(self.cache_dir, 'certspotter_req_logs')
        os.makedirs(self.log_dir, exist_ok=True)

    async def scrape(self):
        """Main scraping method."""
        certspotter_output = set()
        async with aiohttp.ClientSession() as session:
            response_json = await self._fetch_certspotter_data(session)
        # Run file writing and domain extraction concurrently
        certspotter_output, _ = await asyncio.gather(
            self._extract_domains(response_json),
            self._write_json_response(response_json)
        )
        # Write only domains to file
        await self._write_domains_to_file(certspotter_output)
        return list(certspotter_output)

    async def _fetch_certspotter_data(self, session):
        """Send GET request to CertSpotter API and retrieve JSON response."""
        async with session.get(
                f'https://api.certspotter.com/v1/issuances?domain={self.domain}&expand=dns_names',
                headers={'Accept': 'application/json'}
        ) as resp:
            return await resp.json(encoding='utf-8')

    async def _write_json_response(self, response_json):
        """Write JSON response to a file asynchronously."""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json'
        )
        async with aiofiles.open(file_path, 'w') as json_request_file:
            await json.dump(response_json, json_request_file, sort_keys=True, indent=4)

    async def _write_domains_to_file(self, certspotter_output):
        """Write extracted domains (no wildcards) to a file asynchronously."""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt'
        )
        async with aiofiles.open(file_path, 'w') as domains_only_file:
            await domains_only_file.write("\n".join(sorted(certspotter_output)))

    async def _extract_domains(self, response_json):
        """Extract domain names from JSON response and clean up wildcard entries."""
        certspotter_output = set()
        for cert_data in response_json:
            for dns_name in cert_data['dns_names']:
                certspotter_output.add(dns_name.lstrip('*.'))
        return certspotter_output


class HackerTargetScraper(BaseScraper):
    """Scraper for HackerTarget API."""

    def __init__(self, domain: str):
        super().__init__(domain)
        self.log_dir = os.path.join(self.cache_dir, 'hackertarget_req_logs')
        os.makedirs(self.log_dir, exist_ok=True)

    async def scrape(self):
        """Main scraping method."""
        hackertarget_output = set()
        async with aiohttp.ClientSession() as session:
            response_text = await self._fetch_hackertarget_data(session)
        if 'API count exceeded' in response_text:
            print('SKIP HackerTarget | Daily Limit Exceeded. (Possible bypass: new IP or use hackertarget.com API Key)')
            return list(hackertarget_output)
        # Run file writing and domain extraction concurrently
        hackertarget_output, _ = await asyncio.gather(
            self._extract_domains(response_text),
            self._write_text_response(response_text)
        )
        # Write extracted domains to file
        await self._write_domains_to_file(hackertarget_output)
        return list(hackertarget_output)

    async def _fetch_hackertarget_data(self, session):
        """Send GET request to HackerTarget API and retrieve text response."""
        async with session.get(f'https://api.hackertarget.com/hostsearch/?q={self.domain}') as resp:
            return await resp.text(encoding='utf-8')

    async def _write_text_response(self, response_text):
        """Write text response to a file asynchronously."""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_TEXT.txt'
        )
        async with aiofiles.open(file_path, 'w') as text_request_file:
            await text_request_file.write(response_text)

    async def _write_domains_to_file(self, hackertarget_output):
        """Write extracted domains to a file asynchronously."""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_domains.txt'
        )
        async with aiofiles.open(file_path, 'w') as domains_only_file:
            await domains_only_file.write("\n".join(sorted(hackertarget_output)))

    async def _extract_domains(self, response_text):
        """Extract domain names from the text response."""
        hackertarget_output = set()
        for line in response_text.splitlines():
            if "," in line:
                domain = line.split(",")[0]
                hackertarget_output.add(domain)
        return hackertarget_output


class SubdomainGatherer:
    """Class to gather subdomains using multiple scrapers."""

    def __init__(self, domains: set):
        self.domains = domains
        self.all_subdomains = set()

    async def gather_subdomains(self):
        waf_utils = WAFUtils()
        for domain in self.domains:
            domain_subdomains = set()
            domain_subdomains.update(await self.scrape_domain(domain))
            await self._write_domain_subdomains_to_file(domain, domain_subdomains)
            # Add domain itself
            domain_subdomains.add(domain)
            # And add top-level domain (TLD)
            domain_subdomains.update(await waf_utils.get_top_domains([domain]))
            # Add subdomains to overall set
            self.all_subdomains.update(domain_subdomains)
        # Write all domains/subdomains to a final file
        await self._write_all_subdomains_to_file()
        return sorted(self.all_subdomains)

    async def scrape_domain(self, domain: str):
        """Method to scrape multiple sources for a given domain."""
        subdomains = set()
        scrapers = [
            # Add other scrapers here (DnsDumpsterScraper, CertSpotterScraper, etc.)
            CrtShScraper(domain),
            # DnsDumpsterScraper(domain),
            # CertSpotterScraper(domain),
            # HackerTargetScraper(domain),
        ]
        for scraper in scrapers:
            subdomains.update(await scraper.scrape())
        return subdomains

    async def _write_domain_subdomains_to_file(self, domain: str, subdomains: set):
        file_path = os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                  f'../../cache/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_subdomains.txt'))
        async with aiofiles.open(file_path, 'a') as file:
            await file.write("\n".join(sorted(subdomains)))

    async def _write_all_subdomains_to_file(self):
        file_path = os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                  f'../../cache/ALL_DOMAINS_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.txt'))
        async with aiofiles.open(file_path, 'a') as file:
            await file.write("\n".join(sorted(self.all_subdomains)))
