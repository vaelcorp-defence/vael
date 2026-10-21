from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from typing import Set, List
from .http_engine import HTTPEngine

class Crawler:
    def __init__(self, engine: HTTPEngine):
        self.engine = engine
        self.visited: Set[str] = set()
        self.found_urls: List[str] = []
        self.vulnerable_targets: List[dict] = [] 

    async def crawl(self, start_url: str, max_pages: int = 10):
        queue = [start_url]
        
        while queue and len(self.visited) < max_pages:
            url = queue.pop(0).split('#')[0]
            
            if url in self.visited:
                continue
                
            self.visited.add(url)
            print(f"[*] Crawling: {url}")
            
            response = await self.engine.request("GET", url)
            if not response or response.status_code != 200:
                continue
                
            self.found_urls.append(url)
            
            # 1. Extract parameters from URLs (GET requests)
            if "?" in url and "=" in url:
                self.vulnerable_targets.append({
                    "url": url,
                    "method": "GET",
                    "params": {}
                })
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 2. Extract links for the queue
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                
                if urlparse(next_url).scheme in ['http', 'https']:
                    if urlparse(next_url).netloc == urlparse(start_url).netloc:
                        if next_url not in self.visited:
                            queue.append(next_url)

            # 3. Extract parameters from FORMS automatically
            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_url = urljoin(url, action)
                method = form.get('method', 'GET').upper()
                
                if urlparse(form_url).netloc != urlparse(start_url).netloc:
                    continue
                    
                inputs = form.find_all(['input', 'textarea'])
                params = {}
                for inp in inputs:
                    name = inp.get('name')
                    if name and inp.get('type') not in ['submit', 'button', 'checkbox', 'radio']:
                        params[name] = "vael_test"
                
                if params:
                    if method == 'GET':
                        test_url = f"{form_url}?{urlencode(params)}"
                        self.vulnerable_targets.append({
                            "url": test_url,
                            "method": "GET",
                            "params": {}
                        })
                    else:
                        self.vulnerable_targets.append({
                            "url": form_url,
                            "method": "POST",
                            "params": params
                        })
