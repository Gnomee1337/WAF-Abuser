import os
import aiofiles
from abc import ABC, abstractmethod


class BaseScraper(ABC):
    """Abstract base class for all scrapers."""

    def __init__(self, domain: str):
        self.domain = domain
        self.cache_dir = os.path.normpath(os.path.join(os.path.realpath(__file__), '../../../cache'))
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
