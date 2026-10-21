from urllib.parse import urlparse
from ..http_engine import HTTPEngine

class SensitiveFilesSkill:
    def __init__(self):
        self.name = "Sensitive Files"
        # Generic real-world targets
        self.targets = [
            (".env", "DB_PASSWORD=", "High"),
            (".git/config", "[core]", "High"),
            (".aws/credentials", "aws_access_key_id", "High"),
            ("id_rsa", "BEGIN RSA PRIVATE KEY", "High"),
            ("web.config", "<configuration>", "High"),
            ("database.sql", "CREATE TABLE", "High"),
            ("backup.zip", "PK\x03\x04", "Medium"),
            ("backup.sql", "INSERT INTO", "High"),
            ("config.php.bak", "<?php", "High"),
            (".htaccess", "<IfModule", "Medium"),
            ("sitemap.xml", "<urlset", "Info"),
            ("swagger.json", "swagger", "Low"),
            ("api-docs", "swagger", "Low"),
            ("server-status", "Apache Server Status", "Medium"),
            ("phpinfo.php", "<title>phpinfo()</title>", "High"),
            (".DS_Store", "Bud1", "Low"),
            ("composer.json", "require", "Low")
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        
        parsed = urlparse(base_url)
        parsed_base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path, signature, severity in self.targets:
            test_url = f"{parsed_base}/{path}"
            
            response = await engine.request("GET", test_url)
            
            if not response:
                continue
                
            if response.status_code == 200:
                # If the file is a binary (.zip, .DS_Store), we just check status 200
                if path.endswith(('.zip', '.DS_Store')):
                    is_vulnerable = True
                else:
                    # For text files, check if the signature is present
                    is_vulnerable = signature.lower() in response.text.lower()
                
                if is_vulnerable:
                    poc = f"Open this URL in a browser or run:\ncurl {test_url}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Exposed Sensitive File: {path}",
                        "severity": severity,
                        "evidence": f"File returned HTTP 200 and matches expected content.",
                        "poc": poc
                    })
                    
        return findings
