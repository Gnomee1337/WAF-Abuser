import asyncio
import ipaddress
import logging
import os
import aiofiles
import aiohttp
import tldextract
from html_similarity import similarity
from itertools import chain


class WAFUtils:
    def __init__(self):
        self.logger = self._setup_logger()
        self.custom_tldextract = self._initialize_tldextract()

    @staticmethod
    def _setup_logger():
        """Sets up the logger for the class."""
        logging.basicConfig()
        return logging.getLogger(__name__)

    @staticmethod
    def _initialize_tldextract():
        """Initializes TLDExtract with a custom cache directory."""
        cache_dir = os.path.normpath(os.path.join(os.path.realpath(__file__), '../../cache/tldextract-cache'))
        return tldextract.TLDExtract(cache_dir=cache_dir)

    async def get_page_content(self, get_page: str) -> str:
        """Fetches the content of a webpage."""
        url = f"https://{get_page}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url=url, ssl=False, timeout=aiohttp.ClientTimeout(total=3)
                                       ) as response:
                    return await response.text()
            except aiohttp.ClientConnectorError as e:
                self.logger.debug(f"Connection Error with {get_page}: {e}")
                self.logger.info(f"Skipped | Error with {get_page}")
                return ""
            except asyncio.TimeoutError:
                self.logger.info(f"Timeout occurred for {get_page}")
                return ""
            except Exception as e:
                self.logger.error(f"Unexpected error with {get_page}: {e}")
                return ""

    async def compare_two_pages(self, original_page: str, check_page: str):
        """Compares two HTML pages and returns their similarity."""
        url = f"http://{check_page}"
        async with aiohttp.ClientSession() as session:
            try:
                # Fetch the check_page content
                async with session.get(url=url, ssl=False, timeout=aiohttp.ClientTimeout(total=3)
                                       ) as check_resp:
                    check_page_response = await check_resp.text()
                # Compare original_page with check_page and return list[tuple(IP,Similarity_Percentage),...]
                similarity_percentage = int(similarity(str(original_page), str(check_page_response), k=0.3) * 100)
                return (check_page, similarity_percentage)
            except aiohttp.ClientConnectorError as e:
                self.logger.debug(f"Connection Error with {check_page}: {e}")
                self.logger.info(f"Skipped | Error with {check_page}")
                return (check_page, 0)
            except asyncio.TimeoutError:
                self.logger.info(f"Timeout occurred for {check_page}")
                return (check_page, 0)
            except Exception as e:
                self.logger.error(f"Unexpected error with {check_page}: {e}")
                return (check_page, 0)

    async def parse_public_waf_ranges(self) -> list[str]:
        """Reads WAF ranges from the PublicWAFs.txt file."""
        file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../data/PublicWAFs.txt')
        async with aiofiles.open(file_path, mode='r') as public_WAFs:
            # Read the rest of the lines, strip, and return them as a list
            return [line.strip() for line in await public_WAFs.readlines()]

    async def filter_out_waf_ips(self, ips_to_check: set[str]) -> set[str]:
        """Filters out IPs that are in WAF ranges."""
        # Parse the WAF IP ranges
        waf_ips_with_cidr = await self.parse_public_waf_ranges()
        # Flatten all WAF IPs into a set
        all_waf_ips = set(chain.from_iterable(ipaddress.ip_network(waf_ip) for waf_ip in waf_ips_with_cidr))
        # Filter the IPs that are not in WAF ranges
        return {ip for ip in ips_to_check if ipaddress.ip_address(ip) not in all_waf_ips}

    async def get_top_domains(self, domains: list[str]) -> list[str]:
        """Extracts top-level domains from a list of domains."""
        # Filter out empty or None entries from the list
        domains = [domain for domain in domains if domain]
        # Extract domain and suffix, and combine them to get the full top-level domain
        return [
            f"{extracted.domain}.{extracted.suffix}"
            for domain in domains
            if (extracted := self.custom_tldextract(domain))
        ]
