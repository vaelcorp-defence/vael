import re
from ..http_engine import HTTPEngine

class VulnJSSkill:
    def __init__(self):
        self.name = "Vulnerable JS Library"
        # Known vulnerable versions
        self.vuln_patterns = [
            (r"jquery-1\.\d+\.\d+", "jQuery 1.x (Multiple XSS CVEs)"),
            (r"jquery-2\.\d+\.\d+", "jQuery 2.x (Multiple XSS CVEs)"),
            (r"angular\.min\.js", "AngularJS (EOL, multiple XSS CVEs)"),
            (r"bootstrap-3\.\d+\.\d+", "Bootstrap 3.x (XSS CVE-2018-14041)"),
            (r"lodash-4\.17\.[0-9]", "Lodash 4.17.x (Prototype Pollution CVE-2020-8203)")
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        response = await engine.request("GET", root_url)
        if not response:
            return findings
            
        # Find all JS files
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', response.text)
        
        for js_path in js_files:
            if js_path.startswith('http'):
                js_url = js_path
            elif js_path.startswith('/'):
                js_url = f"{root_url}{js_path}"
            else:
                js_url = f"{root_url}/{js_path}"
                
            # Check the filename itself for versions
            for pattern, vuln_name in self.vuln_patterns:
                if re.search(pattern, js_path, re.IGNORECASE):
                    findings.append({
                        "skill": self.name,
                        "target": js_url,
                        "issue": f"Vulnerable JS Library Detected: {vuln_name}",
                        "severity": "Medium",
                        "evidence": f"The application includes a JS file matching the vulnerable pattern: {pattern}",
                        "poc": f"Check the source code at:\n{js_url}"
                    })

        return findings
