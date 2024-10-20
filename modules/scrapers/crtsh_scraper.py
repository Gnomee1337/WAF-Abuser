import os
import aiohttp
import datetime
import asyncio
import aiofiles
import json
from itertools import chain

from modules.scrapers.json_scraper import JsonScraper


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

    async def _fetch_crtsh_data(self, retries=3, delay=5):
        """Fetch JSON data from crt.sh"""
        url = f'https://crt.sh/?q={self.domain}&output=json'
        for attempt in range(retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=30) as resp:
                        if resp.status != 200:
                            print(f"Error: crt.sh Received status code {resp.status} on attempt {attempt + 1}")
                            continue
                        # Check if the response is in JSON format
                        content_type = resp.headers.get('Content-Type', '').lower()
                        if 'application/json' in content_type:
                            return await resp.json()
                        else:
                            # If not JSON, treat it as text (likely an HTML error page)
                            text_response = await resp.text()
                            print(f"crt.sh Unexpected content type: {content_type}")
                            # Print part of the response for debugging
                            print("crt.sh Response content: {text_response[:500]}")
                            return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f"crt.sh request error on attempt {attempt + 1}: {e}")
                await asyncio.sleep(delay)
        print("All crt.sh attempts failed.")
        return None

    async def _write_json_response(self, response_json):
        """Write the raw JSON response to a file"""
        file_path = os.path.join(
            self.log_dir, f'{self.domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.json'
        )
        async with aiofiles.open(file_path, 'w') as json_file:
            await json_file.write(json.dumps(response_json, sort_keys=True, indent=4))

    def _extract_and_filter_domains(self, response_json):
        """Extract and filter domains from the JSON response"""
        # Check if response_json is None before attempting to process it
        if response_json is None:
            print("Error: No valid data returned from crt.sh")
            return []
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
