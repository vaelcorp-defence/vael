import httpx
import asyncio
from typing import Optional
from .scope import ScopeManager, ScopeError

class HTTPEngine:
    def __init__(self, scope_manager: ScopeManager, max_concurrency: int = 5, timeout: int = 10, cookie_string: str = None, bearer_token: str = None):
        self.scope = scope_manager
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.request_count = 0
        self.cookie_string = cookie_string
        self.bearer_token = bearer_token
        
        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        if self.cookie_string:
            browser_headers["Cookie"] = self.cookie_string
            
        if self.bearer_token:
            browser_headers["Authorization"] = f"Bearer {self.bearer_token}"
        
        self.client = httpx.AsyncClient(
            timeout=timeout, 
            follow_redirects=False,
            headers=browser_headers
        )

    async def close(self):
        await self.client.aclose()

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            if not self.scope.is_authorized(url):
                return None
        except ScopeError as e:
            print(f"[BLOCKED] {e}")
            return None

        async with self.semaphore:
            self.request_count += 1
            await asyncio.sleep(0.1)
            
            try:
                response = await self.client.request(method, url, **kwargs)
                
                if response.is_redirect:
                    redirect_url = str(response.next_request.url)
                    try:
                        self.scope.validate_redirect(url, redirect_url)
                        response = await self.client.request("GET", redirect_url)
                    except ScopeError as e:
                        print(f"[REDIRECT BLOCKED] {e}")
                        return response 

                return response
                
            except httpx.RequestError as e:
                print(f"[NETWORK ERROR] {method} {url} - {e}")
                return None
