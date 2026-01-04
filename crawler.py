import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class Crawler:
    def __init__(self, base_url, max_pages=200):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(self.base_url).netloc
        self.visited = set()
        self.max_pages = max_pages

    def start(self):
        return self._crawl(self.base_url)

    def _same_domain(self, url):
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def _crawl(self, url):
        if len(self.visited) >= self.max_pages:
            return []

        if url in self.visited:
            return []

        self.visited.add(url)

        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return []

        links = []

        for link_tag in soup.find_all("a", href=True):
            link = urljoin(url, link_tag["href"]).split("#")[0].rstrip("/")

            if self._same_domain(link) and link not in self.visited:
                links.append(link)

        # Depth-first crawl
        all_links = []
        for link in links:
            all_links.append(link)
            all_links.extend(self._crawl(link))

        # unique
        return list(dict.fromkeys(all_links))
