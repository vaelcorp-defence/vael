from ..http_engine import HTTPEngine

class HTTPMethodSkill:
    def __init__(self):
        self.name = "HTTP Method Tampering"
        self.methods = ["TRACE", "PUT", "DELETE", "PATCH"]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        # Test against a common endpoint
        test_url = f"{root_url}/api/users"
        
        for method in self.methods:
            response = await engine.request(method, test_url)
            
            if not response:
                continue
                
            # If TRACE is enabled, it will echo our request back
            if method == "TRACE" and response.status_code == 200 and "TRACE" in response.text:
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": "HTTP TRACE Method Enabled (Cross-Site Tracing)",
                    "severity": "Medium",
                    "evidence": "Server responded with 200 OK and echoed the TRACE request.",
                    "poc": f"Run this to verify:\ncurl -X TRACE {test_url}"
                })
                
            # If PUT or DELETE return 200 OK/201 Created without authorization, it's dangerous
            elif method in ["PUT", "DELETE"] and response.status_code in [200, 201, 204]:
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": f"Dangerous HTTP Method Enabled: {method}",
                    "severity": "High",
                    "evidence": f"Server accepted a {method} request without obvious authorization.",
                    "poc": f"Run this to verify:\ncurl -X {method} {test_url}"
                })
                
        return findings
