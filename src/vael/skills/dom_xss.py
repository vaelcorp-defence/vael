from playwright.async_api import async_playwright
from ..http_engine import HTTPEngine
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

class DOMXSSSkill:
    def __init__(self):
        self.name = "DOM-Based XSS"
        self.payload = "<img src=x onerror=window.vael_dom_xss=true>"

    async def run(self, url: str, engine_user_a: HTTPEngine, cookie_string: str = None) -> list:
        findings = []
        
        # 1. Prepare the test URLs (Hash and Query String)
        base_url = url.split('#')[0]
        test_urls = [f"{base_url}#{self.payload}"] # Hash test
        
        # Add query param test
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        for param in params:
            params[param] = [self.payload]
        new_query = urlencode(params, doseq=True)
        test_urls.append(urlunparse(parsed._replace(query=new_query)))
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                
                context_options = {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                }
                if cookie_string:
                    context_options["extra_http_headers"] = {"Cookie": cookie_string}
                    
                context = await browser.new_context(**context_options)
                page = await context.new_page()
                
                for test_url in test_urls:
                    await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                    await page.wait_for_timeout(2000)
                    
                    is_vulnerable = await page.evaluate("window.vael_dom_xss === true")
                    
                    if is_vulnerable:
                        poc = f"Open this URL in a browser to execute the DOM XSS:\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": "DOM-Based XSS",
                            "severity": "High",
                            "evidence": "The browser's JavaScript executed the injected payload.",
                            "poc": poc
                        })
                        break # Found one, move to next target
                    
                await browser.close()
        except Exception:
            pass
            
        return findings
