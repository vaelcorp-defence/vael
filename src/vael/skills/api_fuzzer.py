from ..http_engine import HTTPEngine

class APIFuzzerSkill:
    def __init__(self):
        self.name = "Forced API Browsing & IDOR"
        # Generic REST API patterns used by thousands of sites
        self.target_endpoints = [
            # Generic user/profile endpoints
            "/api/v1/me", "/api/v1/user", "/api/v1/users", 
            "/api/v1/user/1", "/api/v1/user/2",
            "/api/v1/users/1", "/api/v1/users/2",
            "/api/me", "/api/user", "/api/users",
            
            # Generic basket/cart endpoints (Classic IDOR targets)
            "/api/v1/basket/1", "/api/v1/basket/2",
            "/api/v1/baskets/1", "/api/v1/baskets/2",
            "/api/v1/cart/1", "/api/v1/carts/1",
            
            # Generic admin/config endpoints
            "/api/v1/admin", "/api/admin", "/api/v1/config",
            "/api/config", "/api/v1/settings", "/api/settings",
            
            # Generic observability/metrics
            "/metrics", "/api/v1/status", "/api/status",
            
            # Common older API versions
            "/api/user/1", "/api/basket/1", "/api/cart/1"
        ]
        self.ignored_endpoints = ["/search", "/languages", "/quantitys"]
        self.sensitive_keys = ["email", "password", "token", "role", "username", "address", "phone", "secret", "key", "credit", "hash"]

    async def run(self, base_url: str, engine_user_a: HTTPEngine, engine_user_b: HTTPEngine = None) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        for endpoint in self.target_endpoints:
            if any(ignored in endpoint.lower() for ignored in self.ignored_endpoints):
                continue

            test_url = f"{root_url}{endpoint}"
            
            # 1. Test IDOR (Compare User A and User B)
            if engine_user_b:
                resp_a = await engine_user_a.request("GET", test_url)
                resp_b = await engine_user_b.request("GET", test_url)
                
                if resp_a and resp_b and resp_a.status_code == 200 and resp_b.status_code == 200:
                    # If both get 200 OK, and the response sizes are exactly the same, it's an IDOR
                    if len(resp_a.text) == len(resp_b.text) and len(resp_a.text) > 10 and "login" not in resp_b.text.lower():
                        poc = f"1. Log in as User A. Visit: {test_url}\n2. Log in as User B. Visit the SAME URL: {test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Forced IDOR at {endpoint}",
                            "severity": "Critical",
                            "evidence": f"User B accessed User A's resource. Both responses were exactly {len(resp_a.text)} bytes.",
                            "poc": poc
                        })
            
            # 2. Test Unauthenticated Data Leak (No cookies)
            unauth_headers = {"Cookie": ""}
            resp_unauth = await engine_user_a.request("GET", test_url, headers=unauth_headers)
            
            if resp_unauth and resp_unauth.status_code == 200:
                text_lower = resp_unauth.text.lower()
                
                # Ignore SPA shells or generic login pages
                if "login" in text_lower or "<app-root>" in text_lower or "<div id=\"root\">" in text_lower:
                    continue
                    
                # Look for JSON responses with sensitive keys
                if resp_unauth.text.strip().startswith("[") or resp_unauth.text.strip().startswith("{"):
                    if any(key in text_lower for key in self.sensitive_keys) and "error" not in text_lower:
                        poc = f"Visit this URL in a private browser (no cookies):\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Unauthenticated API Data Leak at {endpoint}",
                            "severity": "High",
                            "evidence": f"Endpoint returned sensitive JSON data without authentication.",
                            "poc": poc
                        })

        return findings
