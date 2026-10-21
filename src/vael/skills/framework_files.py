from urllib.parse import urlparse
from ..http_engine import HTTPEngine

class FrameworkFilesSkill:
    def __init__(self):
        self.name = "Framework & Config Exposure"
        # Generic files used by real-world frameworks
        self.targets = [
            # Spring Boot Actuator (Enterprise Java)
            ("/actuator", "actuator", "High"),
            ("/actuator/env", "activeProfiles", "Critical"),
            ("/actuator/health", "\"status\":\"UP\"", "Info"),
            ("/actuator/heapdump", "PK\\x03\\x04", "Critical"),
            ("/actuator/trace", "\"traces\"", "Medium"),
            ("/actuator/mappings", "\"mappings\"", "Medium"),
            # Laravel
            ("/telescope", "Telescope", "High"),
            ("/storage/logs/laravel.log", "local.ERROR", "High"),
            ("/.env.example", "APP_KEY=", "Medium"),
            # Django
            ("/static/admin/css/base.css", "admin", "Low"),
            ("/api-auth/login/", "Django", "Low"),
            # ASP.NET
            ("/elmah.axd", "Error Log", "High"),
            ("/trace.axd", "Application Trace", "Medium"),
            ("/WebResource.axd", "WebResource", "Low"),
            # WordPress
            ("/wp-login.php", "WordPress", "Low"),
            ("/xmlrpc.php", "XML-RPC", "Medium"),
            ("/wp-config.php.bak", "DB_PASSWORD", "Critical"),
            ("/wp-json/wp/v2/users", "\"slug\"", "Medium"),
            # Generic CI/CD and Docker
            ("/.git/config", "[core]", "High"),
            ("/.gitlab-ci.yml", "script:", "Medium"),
            ("/.github/workflows/main.yml", "on:", "Medium"),
            ("/Jenkinsfile", "pipeline", "Medium"),
            ("/Dockerfile", "FROM", "Low"),
            ("/docker-compose.yml", "services:", "Medium"),
            # Database files
            ("/database.sqlite", "SQLite format", "Critical"),
            ("/db.sqlite3", "SQLite format", "Critical"),
            ("/data.db", "SQLite format", "Critical"),
            # Generic backup files
            ("/.env.bak", "DB_PASSWORD=", "Critical"),
            ("/.env.old", "DB_PASSWORD=", "Critical"),
            ("/config.php.bak", "<?php", "High"),
            ("/config.yml", "password", "Medium"),
            ("/settings.py", "SECRET_KEY", "High"),
            ("/appsettings.json", "ConnectionStrings", "High"),
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Get baseline to avoid false positives on SPA shells
        baseline = await engine.request("GET", root_url)
        baseline_len = len(baseline.text) if baseline else 0
        
        for path, signature, severity in self.targets:
            test_url = f"{root_url}{path}"
            response = await engine.request("GET", test_url)
            
            if not response or response.status_code != 200:
                continue
                
            text = response.text
            
            # Skip SPA shells
            if "<app-root>" in text or "<div id=\"root\">" in text or "<div id=\"app\">" in text:
                continue
                
            # Skip if identical to root
            if abs(len(text) - baseline_len) < 50:
                continue
            
            # Verify the signature
            if signature.lower() in text.lower() or (signature.startswith("PK") and text.startswith("PK")):
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": f"Exposed Framework File: {path}",
                    "severity": severity,
                    "evidence": f"File is accessible and contains the expected signature.",
                    "poc": f"Visit this URL in a browser:\n{test_url}"
                })
                
        return findings

