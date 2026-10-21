from ..http_engine import HTTPEngine

class CSRFSkill:
    def __init__(self):
        self.name = "CSRF (Cross-Site Request Forgery)"

    async def run(self, url: str, engine: HTTPEngine) -> list:
        findings = []
        
        response = await engine.request("GET", url)
        if not response:
            return findings

        # Check all cookies set by the server
        set_cookie_headers = response.headers.get_list("set-cookie")
        
        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()
            
            # Extract cookie name
            cookie_name = cookie_str.split("=")[0]
            
            # If the cookie has no SameSite attribute, or SameSite=None (without Secure), it's a CSRF risk
            if "samesite" not in cookie_lower:
                findings.append({
                    "skill": self.name,
                    "target": url,
                    "issue": f"Missing SameSite Attribute on Cookie '{cookie_name}'",
                    "severity": "Medium",
                    "evidence": f"The cookie '{cookie_name}' is set without the SameSite attribute, making it vulnerable to Cross-Site Request Forgery.",
                    "poc": f"Intercept the response for {url} in Burp Suite and check the Set-Cookie header."
                })
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                findings.append({
                    "skill": self.name,
                    "target": url,
                    "issue": f"Insecure SameSite=None Configuration on Cookie '{cookie_name}'",
                    "severity": "Medium",
                    "evidence": f"The cookie '{cookie_name}' is set to SameSite=None without the Secure flag.",
                    "poc": f"Intercept the response for {url} in Burp Suite and check the Set-Cookie header."
                })
                
        return findings
