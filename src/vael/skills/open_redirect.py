import urllib.parse
from ..http_engine import HTTPEngine

class OpenRedirectSkill:
    def __init__(self):
        self.name = "Open Redirect"
        self.evil_url = "https://evil-vaelcorp.com"
        # Expanded generic redirect parameters
        self.redirect_params = [
            "next", "url", "redirect", "return", "returnUrl", "redirect_uri", 
            "target", "destination", "callback", "continue", "dest", "go", "view"
        ]

    async def run(self, target: dict, engine: HTTPEngine) -> list:
        findings = []
        
        url = target["url"]
        method = target["method"]
        
        if method != "GET":
            return findings

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return findings

        for param_name in params:
            if any(rp in param_name.lower() for rp in self.redirect_params):
                test_params = params.copy()
                test_params[param_name] = [self.evil_url]
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                
                response = await engine.request("GET", test_url)
                if not response:
                    continue
                    
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get("Location", "")
                    if "evil-vaelcorp.com" in location:
                        poc = f"Open this URL in a browser to verify the redirect:\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Open Redirect in parameter '{param_name}'",
                            "severity": "Medium",
                            "evidence": f"Server returned a {response.status_code} redirect to {location}",
                            "poc": poc
                        })
                        
        return findings
