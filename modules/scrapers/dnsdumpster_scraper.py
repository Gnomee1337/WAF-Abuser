import os
import aiohttp
import datetime
import aiofiles
from bs4 import BeautifulSoup

from modules.scrapers.base_scraper import BaseScraper


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
