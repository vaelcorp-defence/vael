from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright

class JSCrawler:
    def __init__(self, scope_manager, cookie_string: str = None):
        self.scope = scope_manager
        self.cookie_string = cookie_string
        self.found_urls = set()
        self.vulnerable_targets = [] 
        self.api_targets = set()

    def _intercept_request(self, request):
        """Listens to background XHR/Fetch requests (API calls)"""
        if request.resource_type in ["xhr", "fetch"]:
            url = request.url
            method = request.method
            
            if "socket.io" in url.lower():
                return
                
            if any(ext in url.lower() for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico"]):
                return
                
            try:
                if self.scope.is_authorized(url):
                    if url not in self.api_targets:
                        self.api_targets.add(url)
                        print(f"    [API DISCOVERED] {method} {url}")
                        self.vulnerable_targets.append({
                            "url": url,
                            "method": method,
                            "params": {}
                        })
            except Exception:
                pass

    async def crawl(self, start_url: str, max_pages: int = 5):
        async with async_playwright() as p:
            # Use headless=False and stealth arguments to bypass WAFs/CAPTCHAs
            browser = await p.chromium.launch(
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-infobars",
                    "--no-sandbox"
                ]
            )
            
            context_options = {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "viewport": {"width": 1920, "height": 1080},
                "device_scale_factor": 1,
                "is_mobile": False,
                "has_touch": False,
                "locale": "en-US",
                "timezone_id": "America/New_York",
                "ignore_https_errors": True
            }
            
            if self.cookie_string:
                context_options["extra_http_headers"] = {"Cookie": self.cookie_string}

            context = await browser.new_context(**context_options)
            page = await context.new_page()
            
            page.on("request", self._intercept_request)
            
            # Hide the webdriver flag
            await page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            queue = [start_url]
            
            while queue and len(self.found_urls) < max_pages:
                url = queue.pop(0).split('#')[0]
                
                if url in self.found_urls:
                    continue

                try:
                    if not self.scope.is_authorized(url):
                        continue
                except Exception:
                    continue

                print(f"[*] JS Crawling: {url}")
                
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    
                    # Wait 5 seconds to allow React/Next/SPA to render, fire APIs, and solve CAPTCHAs
                    await page.wait_for_timeout(5000)
                    
                    self.found_urls.add(url)
                    
                    # 1. Extract standard links
                    try:
                        links = await page.eval_on_selector_all("a", "elements => elements.map(e => e.href)")
                    except Exception:
                        links = []
                        
                    for link in links:
                        if link and urlparse(link).netloc == urlparse(start_url).netloc:
                            if "to=http" in link or "url=http" in link:
                                continue
                                
                            normalized_link = link.rstrip('/')
                            if normalized_link not in self.found_urls and normalized_link not in queue:
                                queue.append(normalized_link)
                                if "?" in normalized_link and "=" in normalized_link:
                                    self.vulnerable_targets.append({
                                        "url": normalized_link,
                                        "method": "GET",
                                        "params": {}
                                    })

                    # 2. Extract Forms dynamically rendered by React/Vue
                    try:
                        forms = await page.evaluate("""
                            () => {
                                return Array.from(document.querySelectorAll('form')).map(f => {
                                    return {
                                        action: f.action || window.location.href,
                                        method: f.method || 'GET',
                                        inputs: Array.from(f.querySelectorAll('input, textarea')).map(i => i.name).filter(n => n)
                                    };
                                });
                            }
                        """)
                    except Exception:
                        forms = []
                        
                    for form in forms:
                        action_url = form['action']
                        if urlparse(action_url).netloc != urlparse(start_url).netloc:
                            continue
                            
                        if form['inputs']:
                            if form['method'].upper() == 'GET':
                                query = "&".join([f"{name}=vael_test" for name in form['inputs']])
                                test_url = f"{action_url}?{query}"
                                self.vulnerable_targets.append({"url": test_url, "method": "GET", "params": {}})
                            else:
                                # It's a POST form (Login, Register, Feedback, etc.)
                                params = {name: "vael_test" for name in form['inputs']}
                                self.vulnerable_targets.append({
                                    "url": action_url, 
                                    "method": "POST", 
                                    "params": params
                                })

                except Exception as e:
                    print(f"[JS CRAWLER ERROR] {url} - {e}")
                    continue

            await browser.close()
