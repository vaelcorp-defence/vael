from ..http_engine import HTTPEngine

class APIParamFuzzerSkill:
    def __init__(self):
        self.name = "API Parameter Fuzzer"
        self.payloads = [
            "?id=1", "?user_id=1", "?account=1", "?admin=true", "?debug=1", "?role=admin"
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        # Removed /whoami and /me to prevent false positives
        endpoints = ["/api/users", "/api/v1/users", "/api/admin", "/api/config", "/api/feedbacks", "/rest/products"]
        
        for endpoint in endpoints:
            base_test = f"{root_url}{endpoint}"
            
            for payload in self.payloads:
                test_url = f"{base_test}{payload}"
                response = await engine.request("GET", test_url)
                
                if response and response.status_code == 200:
                    text_lower = response.text.lower()
                    
                    # Ignore standard React/Angular shells
                    if "<app-root>" in text_lower or "<div id=\"root\">" in text_lower:
                        continue
                        
                    # If we get sensitive data
                    if "admin" in text_lower or "password" in text_lower or "email" in text_lower:
                        poc = f"Visit this URL to access sensitive data:\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"Sensitive Data Exposure via parameter {payload}",
                            "severity": "High",
                            "evidence": f"Endpoint returned sensitive data when appending {payload}.",
                            "poc": poc
                        })
                        break # Move to next endpoint
        return findings
