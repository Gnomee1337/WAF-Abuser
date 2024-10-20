import aiohttp
from modules.scrapers.base_scraper import BaseScraper


class JsonScraper(BaseScraper):
    """Abstract class for scrapers that expect JSON responses."""

    async def fetch_json(self, url: str):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={'Accept': 'application/json'}) as resp:
                return await resp.json(encoding='utf-8')
