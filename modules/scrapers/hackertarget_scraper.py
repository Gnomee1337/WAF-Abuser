import os
import aiohttp
import datetime
import asyncio
import aiofiles

from modules.scrapers.base_scraper import BaseScraper


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
        async with session.get(f'https://api.hackertarget.com/hostsearch/?q={self.domain}', timeout=30) as resp:
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
