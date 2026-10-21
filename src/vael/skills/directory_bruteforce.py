from ..http_engine import HTTPEngine

class DirectoryBruteforceSkill:
    def __init__(self):
        self.name = "Directory Bruteforce"
        # Generic paths found on thousands of real web apps (WordPress, Node, Django, etc.)
        self.paths = [
            # Directories
            "/admin", "/dashboard", "/api", "/api/v1", "/api/v2", "/graphql", "/rest", 
            "/metrics", "/health", "/status", "/debug", "/internal", "/b2b",
            "/ftp", "/files", "/uploads", "/assets", "/static", "/logs", 
            
            # Generic exposed files and backups
            "/backup", "/backups", "/backup.zip", "/backup.tar.gz", "/backup.sql",
            "/config.json", "/config.php.bak", "/web.config.bak", "/.env.bak",
            "/index.php.bak", "/index.html.bak", "/app.js.bak", "/main.js.bak",
            "/database.sql", "/db.sql", "/dump.sql", "/data.zip", "/www.zip",
            
            # Standard files
            "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
            "/swagger.json", "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/openapi.json"
        ]

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        # Get baseline to avoid flagging the default React/Angular SPA shell
        baseline_resp = await engine.request("GET", root_url)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for path in self.paths:
            test_url = f"{root_url}{path}"
            response = await engine.request("GET", test_url)
            
            if not response or response.status_code != 200:
                continue
                
            # If it's just the React/Angular shell, skip it
            if abs(len(response.text) - baseline_len) < 50:
                continue
                
            text_lower = response.text.lower()
            if "<app-root>" in text_lower or "<div id=\"root\">" in text_lower or "<div id=\"app\">" in text_lower:
                continue

            # Determine severity based on the file type
            severity = "Medium"
            if path.endswith(('.zip', '.tar.gz', '.sql', '.bak')):
                severity = "High"
            elif path in ["/admin", "/api", "/graphql", "/metrics"]:
                severity = "Low" # Directories are lower risk unless they leak data

            # It's a real exposed endpoint or file
            poc = f"Visit this URL in a browser:\n{test_url}"
            findings.append({
                "skill": self.name,
                "target": test_url,
                "issue": f"Exposed Directory/File: {path}",
                "severity": severity,
                "evidence": f"Endpoint returned HTTP 200 OK with unique content.",
                "poc": poc
            })
            
        return findings
