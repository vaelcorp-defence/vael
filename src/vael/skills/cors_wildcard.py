from ..http_engine import HTTPEngine

class CORSWildcardSkill:
    def __init__(self):
        self.name = "CORS Wildcard Misconfiguration"

    async def run(self, url: str, engine: HTTPEngine) -> list:
        findings = []
        headers = {"Origin": "https://evil-vaelcorp.com"}
        response = await engine.request("GET", url, headers=headers)
        
        if not response:
            return findings
            
        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_creds = response.headers.get("Access-Control-Allow-Credentials")
        
        # If it reflects the evil origin AND allows credentials
        if allow_origin == "https://evil-vaelcorp.com" and allow_creds == "true":
            findings.append({
                "skill": self.name,
                "target": url,
                "issue": "CORS Misconfiguration (Arbitrary Origin + Credentials)",
                "severity": "Critical",
                "evidence": "Server reflects the Origin header and allows credentials.",
                "poc": f"Run this to verify:\ncurl -H 'Origin: https://evil-vaelcorp.com' -I {url}"
            })
        return findings
