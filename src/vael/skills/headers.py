from ..http_engine import HTTPEngine

class SecurityHeadersSkill:
    def __init__(self):
        self.name = "Security Headers"
        self.required_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy"
        ]

    async def run(self, url: str, engine: HTTPEngine) -> list:
        findings = []
        response = await engine.request("GET", url)
        
        if not response:
            return findings
        if response.status_code in [401, 403, 429]:
            print(f"    [WAF BLOCK] Ignoring {url} (HTTP {response.status_code})")
            return findings

        for header in self.required_headers:
            if header not in response.headers:
                poc = "Run this command to verify:\ncurl -I " + url
                findings.append({
                    "skill": self.name,
                    "target": url,
                    "issue": f"Missing Header: {header}",
                    "severity": "Info",
                    "evidence": f"HTTP {response.status_code} response did not contain {header}.",
                    "poc": poc
                })
                
        return findings
