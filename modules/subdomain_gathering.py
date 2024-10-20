import datetime
import os
import aiofiles

from modules.utility import WAFUtils
from modules.scrapers.crtsh_scraper import CrtShScraper
from modules.scrapers.certspotter_scraper import CertSpotterScraper
from modules.scrapers.dnsdumpster_scraper import DnsDumpsterScraper
from modules.scrapers.hackertarget_scraper import HackerTargetScraper


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
        crtsh_scraper = CrtShScraper(domain)
        dnsdumpster_scraper = DnsDumpsterScraper(domain)
        certspotter_scraper = CertSpotterScraper(domain)
        hackertarget_scraper = HackerTargetScraper(domain)
        subdomains = set()
        scrapers = [
            # Add other scrapers here (DnsDumpsterScraper, CertSpotterScraper, etc.)
            crtsh_scraper,
            dnsdumpster_scraper,
            certspotter_scraper,
            hackertarget_scraper,
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
