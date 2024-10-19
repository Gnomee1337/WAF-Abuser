import datetime
import os
import re
import aiohttp
import dns.resolver
import aiofiles
from bs4 import BeautifulSoup


class IPGatherer:
    def __init__(self):
        self.log_dir = os.path.normpath(os.path.join(os.path.realpath(__file__), '../../cache/viewdnsinfo_req_logs/'))
        os.makedirs(self.log_dir, exist_ok=True)
        self.all_ips = set()

    async def gather_ips(self, domains: set):
        for domain in domains:
            domain_ips = await self._ip_history_viewdnsinfo(domain)
            if domain_ips:
                domain_ips = await self._remove_original_ips(domain, domain_ips)
                await self._write_domain_related_ips_to_file(domain, domain_ips)
                self.all_ips.update(domain_ips)
        await self._write_all_possible_ips_to_file()
        return sorted(self.all_ips)

    async def _ip_history_viewdnsinfo(self, domain: str):
        viewdnsinfo_ips_output = set()
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://viewdns.info/iphistory/?domain={domain}', timeout=30) as resp:
                response_text = await resp.text()
                if "403 Forbidden - Naughty!" in response_text:
                    print(
                        'SKIP Viewdnsinfo | Daily Limit Exceeded. (Possible bypass: new IP or use viewdns.info API Key)')
                    return -403
                # Write HTML response to file
                await self._write_html_response(domain, response_text)
                # Setup soup
                soup = BeautifulSoup(response_text.encode('utf-8'), 'html.parser')
                # Improved regex for IP address extraction
                ip_pattern = re.compile(
                    r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                )
                # Find the table containing the IP addresses
                tables = soup.find_all('table', {'border': '1'})
                for table in tables:  # Iterate over each table found
                    # Iterate through all <td> elements in the table
                    for td in table.find_all('td'):
                        text = td.get_text(strip=True)
                        # Check if the text matches the IP pattern
                        if ip_pattern.match(text):
                            viewdnsinfo_ips_output.add(text)
                # Write only extracted IPs to file
                await self._write_extracted_ips_to_file(domain, viewdnsinfo_ips_output)
        return viewdnsinfo_ips_output

    async def _remove_original_ips(self, domain: str, all_domain_ips: set):
        try:
            # Resolve the original IPs for the given domain
            original_ips = dns.resolver.resolve(domain, 'A')
            for ip in original_ips:
                # Use the .to_text() method to get the string representation of the IP
                all_domain_ips.discard(ip.to_text())
        except dns.exception.DNSException:
            pass  # Handle DNS resolution errors silently
        return all_domain_ips

    async def _write_html_response(self, domain: str, response_text: str):
        file_path = os.path.join(self.log_dir,
                                 f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_HTML.txt')
        async with aiofiles.open(file_path, 'w') as file:
            await file.write(response_text)

    async def _write_extracted_ips_to_file(self, domain: str, viewdnsinfo_ips_output: set):
        file_path = os.path.join(self.log_dir,
                                 f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_only_ips.txt')
        async with aiofiles.open(file_path, 'w') as file:
            await file.write("\n".join(str(ip) for ip in viewdnsinfo_ips_output))

    async def _write_domain_related_ips_to_file(self, domain: str, domain_ips: set):
        file_path = os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                  f'../../cache/{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_IPs.txt'))
        async with aiofiles.open(file_path, 'w') as file:
            await file.write("\n".join(sorted(domain_ips)))

    async def _write_all_possible_ips_to_file(self):
        file_path = os.path.normpath(os.path.join(os.path.realpath(__file__),
                                                  f'../../cache/ALL_DOMAINS_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_IPs.txt'))
        async with aiofiles.open(file_path, 'w') as file:
            await file.write("\n".join(str(ip) for ip in sorted(self.all_ips)))
