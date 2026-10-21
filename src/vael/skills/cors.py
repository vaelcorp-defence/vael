from ..http_engine import HTTPEngine

class CORSSkill:
    def __init__(self):
        self.name = "CORS Misconfiguration"
        self.evil_origin = "https://evil-vaelcorp.com"

    async def run(self, url: str, engine: HTTPEngine) -> list:
        findings = []
        
        headers = {"Origin": self.evil_origin}
        response = await engine.request("GET", url, headers=headers)
        
        if not response:
            return findings

        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_creds = response.headers.get("Access-Control-Allow-Credentials")

        if allow_origin == self.evil_origin:
            severity = "High" if allow_creds == "true" else "Medium"
            poc = f'Run this command to verify:\ncurl -i -s -H "Origin: {self.evil_origin}" {url} | grep -i "access-control"'
            
            findings.append({
                "skill": self.name,
                "target": url,
                "issue": "Insecure CORS Policy",
                "severity": severity,
                "evidence": f"Server reflected the Origin header ({self.evil_origin}). Credentials allowed: {allow_creds}.",
                "poc": poc
            })
            
        return findings
