import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()

    def start(self):
        return self._crawl(self.base_url)

    def _crawl(self, url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            for link_tag in soup.find_all('a', href=True):
                link = urljoin(url, link_tag['href'])
                if self.base_url in link and link not in self.visited:
                    self.visited.add(link)
                    links.append(link)
                    links.extend(self._crawl(link))
            return list(set(links))
        except:
            return []
