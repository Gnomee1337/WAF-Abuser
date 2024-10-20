import os
import aiohttp
import datetime
import asyncio
import aiofiles
import json

from modules.scrapers.base_scraper import BaseScraper


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
                headers={'Accept': 'application/json'},
                timeout=30
        ) as resp:
            return await resp.json(encoding='utf-8')

    async def _write_json_response(self, response_json):
        """Write JSON response to a file asynchronously."""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json'
        )
        async with aiofiles.open(file_path, 'w') as json_request_file:
            # Create the JSON string synchronously
            json_string = json.dumps(response_json, sort_keys=True, indent=4)
            # Write the JSON content to the file asynchronously
            await json_request_file.write(json_string)

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
