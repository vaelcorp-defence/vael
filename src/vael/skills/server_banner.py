from ..http_engine import HTTPEngine

class ServerBannerSkill:
    def __init__(self):
        self.name = "Server Banner Grabbing"

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        
        response = await engine.request("GET", base_url)
        if not response:
            return findings
            
        # Headers that leak version info
        headers_to_check = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        
        for header in headers_to_check:
            value = response.headers.get(header)
            if value:
                # Only flag if it contains numbers (indicating a version)
                if any(char.isdigit() for char in value):
                    findings.append({
                        "skill": self.name,
                        "target": base_url,
                        "issue": f"Server Version Disclosure via '{header}'",
                        "severity": "Info",
                        "evidence": f"Server leaked its version: {header}: {value}",
                        "poc": f"Run this to verify:\ncurl -I {base_url}"
                    })
                    
        return findings
