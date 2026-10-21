import re
from ..http_engine import HTTPEngine

class JSSecretScanner:
    def __init__(self):
        self.name = "JavaScript Secret Scanner"
        self.patterns = {
            "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
            "Google API Key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
            "Generic API Key": r"(?i)api_key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
            "Hardcoded Password": r"(?i)password\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
            "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "Email Address": r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
            "Stripe Key": r"pk_live_[0-9a-zA-Z]{24}",
            "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?"
        }

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        response = await engine.request("GET", root_url)
        if not response:
            return findings
            
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', response.text)
        
        # Common bundles to ensure we check them even if hidden
        common_bundles = ["/main.js", "/polyfills.js", "/runtime.js", "/vendor.js", "/scripts.js", "/app.js"]
        for bundle in common_bundles:
            js_files.append(bundle)
            
        js_files = list(set(js_files))
        
        for js_path in js_files:
            if js_path.startswith('http'):
                js_url = js_path
            elif js_path.startswith('/'):
                js_url = f"{root_url}{js_path}"
            else:
                js_url = f"{root_url}/{js_path}"
                
            js_resp = await engine.request("GET", js_url)
            if not js_resp or js_resp.status_code != 200:
                continue
                
            for secret_name, pattern in self.patterns.items():
                matches = re.findall(pattern, js_resp.text)
                for match in matches:
                    leaked_string = match if isinstance(match, str) else match[0]
                    
                    if len(leaked_string) < 6 or leaked_string.lower() in ['password', 'secret', 'token', 'undefined', 'null']:
                        continue
                        
                    poc = f"Found {secret_name} in {js_url}:\n\n{leaked_string}"
                    findings.append({
                        "skill": self.name,
                        "target": js_url,
                        "issue": f"Exposed Credential/Secret: {secret_name}",
                        "severity": "High",
                        "evidence": f"JavaScript file contains a hardcoded {secret_name}.",
                        "poc": poc
                    })
                    
        return findings
