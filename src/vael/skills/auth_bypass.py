from urllib.parse import urlparse
from ..http_engine import HTTPEngine

class AuthBypassSkill:
    def __init__(self):
        self.name = "Auth Bypass (Force Browsing)"
        # Generic administrative and sensitive paths
        self.target_paths = [
            "/admin",
            "/dashboard",
            "/settings",
            "/profile",
            "/internal",
            "/administrator",
            "/api/admin",
            "/api/v1/admin",
            "/api/users",
            "/api/v1/users",
            "/api/config",
            "/api/settings"
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Explicitly send an empty cookie header to bypass authentication
        empty_cookie_headers = {"Cookie": ""}
        
        for path in self.target_paths:
            test_url = f"{root_url}{path}"
            
            # Request WITHOUT the session cookie
            response = await engine.request("GET", test_url, headers=empty_cookie_headers)
            
            if not response:
                continue
                
            if response.status_code == 200:
                text_lower = response.text.lower()
                
                # Check 1: Is it just a login page?
                if "login" in text_lower or "signin" in text_lower or "unauthorized" in text_lower:
                    continue
                    
                # Check 2: Is it just the SPA (React/Angular/Vue) shell?
                spa_signatures = ["<app-root>", "<div id=\"root\">", "<div id=\"app\">", "<script src=\"main.js", "<script src=\"/static/js/main."]
                if any(sig in text_lower for sig in spa_signatures):
                    continue
                    
                # Check 3: Is it identical to the root page (also requested without cookies)?
                root_resp = await engine.request("GET", root_url, headers=empty_cookie_headers)
                if root_resp and abs(len(response.text) - len(root_resp.text)) < 100:
                    continue

                poc = f"Visit this URL in a private browser (no cookies):\n{test_url}"
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": f"Exposed Protected Endpoint: {path}",
                    "severity": "Critical",
                    "evidence": f"Endpoint returned HTTP 200 OK with unique content without authentication.",
                    "poc": poc
                })
                    
        return findings
