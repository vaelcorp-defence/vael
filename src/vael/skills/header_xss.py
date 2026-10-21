from ..http_engine import HTTPEngine

class HeaderXSSSkill:
    def __init__(self):
        self.name = "HTTP Header XSS"
        self.payload = "<script>alert('header_xss')</script>"
        self.headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        
        for header in self.headers_to_test:
            # Send the payload in the header
            custom_headers = {header: self.payload}
            response = await engine.request("GET", base_url, headers=custom_headers)
            
            if not response:
                continue
                
            # Check if the payload is reflected in the HTML
            if self.payload in response.text:
                findings.append({
                    "skill": self.name,
                    "target": base_url,
                    "issue": f"Reflected XSS via {header} Header",
                    "severity": "High",
                    "evidence": f"The application reflects the {header} header without sanitization.",
                    "poc": f"Run this to verify:\ncurl -H '{header}: {self.payload}' {base_url}"
                })
                
        return findings
