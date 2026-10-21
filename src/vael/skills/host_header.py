from ..http_engine import HTTPEngine

class HostHeaderSkill:
    def __init__(self):
        self.name = "Host Header Injection"

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        evil_host = "evil-vaelcorp.com"
        
        # Send request with malicious Host header
        headers = {"Host": evil_host, "X-Forwarded-Host": evil_host}
        response = await engine.request("GET", base_url, headers=headers)
        
        if not response:
            return findings
            
        # If the app reflects the host header in links or redirects
        if evil_host in response.text:
            findings.append({
                "skill": self.name,
                "target": base_url,
                "issue": "Host Header Injection (Reflected)",
                "severity": "Medium",
                "evidence": f"The application reflects the manipulated Host header ({evil_host}).",
                "poc": f"Run this to verify:\ncurl -H 'Host: {evil_host}' {base_url}"
            })
        return findings
