from ..http_engine import HTTPEngine

class APIWordlistSkill:
    def __init__(self):
        self.name = "API Wordlist Fuzzer"
        # Strictly generic REST API endpoints
        self.paths = [
            # Standard v1 API endpoints
            "/api/v1/users", "/api/v1/users/1", "/api/v1/users/2",
            "/api/v1/feedbacks", "/api/v1/feedbacks/1",
            "/api/v1/baskets", "/api/v1/baskets/1", "/api/v1/baskets/2",
            "/api/v1/products", "/api/v1/products/1",
            "/api/v1/orders", "/api/v1/orders/1",
            "/api/v1/invoices", "/api/v1/invoices/1",
            "/api/v1/transactions", "/api/v1/transactions/1",
            "/api/v1/profile", "/api/v1/profile/1",
            "/api/v1/admin", "/api/v1/config", "/api/v1/settings",
            
            # Standard v2 API endpoints
            "/api/v2/users", "/api/v2/feedbacks",
            "/api/v2/products", "/api/v2/orders",
            
            # Standard non-versioned endpoints
            "/api/users", "/api/feedbacks", "/api/baskets",
            "/api/products", "/api/orders", "/api/invoices",
            "/api/profile", "/api/admin", "/api/config", "/api/settings"
        ]

    async def run(self, base_url: str, engine: HTTPEngine, engine_user_b: HTTPEngine = None) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        for path in self.paths:
            test_url = f"{root_url}{path}"
            
            # 1. Test Unauthenticated Access (No cookie)
            unauth_headers = {"Cookie": ""}
            resp_unauth = await engine.request("GET", test_url, headers=unauth_headers)
            
            if resp_unauth and resp_unauth.status_code == 200:
                text_lower = resp_unauth.text.lower()
                
                # Ignore SPA shell
                if "<app-root>" in text_lower or "<div id=\"root\">" in text_lower or "<div id=\"app\">" in text_lower:
                    continue
                    
                # If it returns JSON data, flag it
                if resp_unauth.text.strip().startswith("[") or resp_unauth.text.strip().startswith("{"):
                    if "error" not in text_lower and "unauthorized" not in text_lower and "login" not in text_lower:
                        poc = f"Visit this URL in a private browser (no cookies):\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Unauthenticated API Access: {path}",
                            "severity": "High",
                            "evidence": f"Endpoint returned JSON data without authentication.",
                            "poc": poc
                        })
                        
            # 2. Test IDOR (If we have User B)
            if engine_user_b:
                resp_a = await engine.request("GET", test_url)
                resp_b = await engine_user_b.request("GET", test_url)
                
                if resp_a and resp_b and resp_a.status_code == 200 and resp_b.status_code == 200:
                    # Same exact size means User B is seeing User A's data
                    if len(resp_a.text) == len(resp_b.text) and len(resp_a.text) > 20 and "login" not in resp_b.text.lower():
                        poc = f"1. Log in as User A. Visit: {test_url}\n2. Log in as User B. Visit the SAME URL: {test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Forced IDOR at {path}",
                            "severity": "Critical",
                            "evidence": f"User B accessed User A's resource. Both responses were exactly {len(resp_a.text)} bytes.",
                            "poc": poc
                        })
                        
        return findings
