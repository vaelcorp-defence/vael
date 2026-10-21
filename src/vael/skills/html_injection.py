import urllib.parse
from ..http_engine import HTTPEngine

class HTMLInjectionSkill:
    def __init__(self):
        self.name = "HTML Injection"
        self.payload = "<h1>VAELCORP</h1>"

    async def run(self, target: dict, engine: HTTPEngine) -> list:
        findings = []
        url = target["url"]
        if target["method"] != "GET":
            return findings

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name in params:
            test_params = params.copy()
            test_params[param_name] = [self.payload]
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
            
            response = await engine.request("GET", test_url)
            if not response:
                continue
                
            if self.payload in response.text:
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": f"HTML Injection in parameter '{param_name}'",
                    "severity": "Medium",
                    "evidence": f"HTML tags were reflected unencoded in the response.",
                    "poc": f"Visit this URL:\n{test_url}"
                })
        return findings
