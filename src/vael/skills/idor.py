import urllib.parse
import re
import base64
import json
from ..http_engine import HTTPEngine

class IDORSkill:
    def __init__(self):
        self.name = "IDOR (Insecure Direct Object Reference)"

    def _extract_user_a_email(self, cookie: str):
        """Extracts User A's email from their JWT token to use as a unique identifier."""
        try:
            if not cookie or "token=" not in cookie:
                return None
            raw_token = cookie.split("token=")[1].split(";")[0]
            payload_b64 = raw_token.split(".")[1]
            rem = len(payload_b64) % 4
            if rem > 0:
                payload_b64 += '=' * (4 - rem)
            decoded = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(decoded)
            return payload.get("data", {}).get("email") or payload.get("email")
        except Exception:
            return None

    async def run(self, target: dict, engine_user_a: HTTPEngine, engine_user_b: HTTPEngine = None, cookie_a: str = None) -> list:
        findings = []
        
        if not engine_user_b or not cookie_a:
            return findings

        email_a = self._extract_user_a_email(cookie_a)
        if not email_a:
            return findings

        url = target["url"]
        method = target["method"]
        
        if method != "GET" or "socket.io" in url.lower():
            return findings

        async def check_idor(test_url):
            # 1. User A requests the resource (to ensure it exists)
            resp_a = await engine_user_a.request("GET", test_url)
            if not resp_a or resp_a.status_code != 200:
                return False, ""
                
            # 2. User B requests the EXACT SAME resource
            resp_b = await engine_user_b.request("GET", test_url)
            if not resp_b or resp_b.status_code != 200:
                return False, ""
                
            # 3. The Proof: Does User B's response contain User A's email?
            # We only check JSON or text responses to avoid binary files
            content_type = resp_b.headers.get("content-type", "").lower()
            if "json" in content_type or "text" in content_type:
                if email_a.lower() in resp_b.text.lower():
                    return True, f"Confirmed IDOR: User B accessed a resource containing User A's email ({email_a})."
                
            return False, ""

        # --- TEST 1: Query Parameters (?id=1) ---
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name, values in params.items():
            if values[0].isdigit():
                test_params = params.copy()
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                
                is_vuln, evidence = await check_idor(test_url)
                if is_vuln:
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Confirmed IDOR in parameter '{param_name}'",
                        "severity": "Critical",
                        "evidence": evidence,
                        "poc": f"1. Log in as User A. Visit: {test_url}\n2. Log in as User B. Visit the SAME URL."
                    })
        
        # --- TEST 2: Path Parameters (/api/users/1) ---
        path_match = re.search(r'/(\d+)(?:$|\?)', url)
        if path_match:
            is_vuln, evidence = await check_idor(url)
            if is_vuln:
                findings.append({
                    "skill": self.name,
                    "target": url,
                    "issue": f"Confirmed IDOR in URL path",
                    "severity": "Critical",
                    "evidence": evidence,
                    "poc": f"1. Log in as User A. Visit: {url}\n2. Log in as User B. Visit the SAME URL."
                })

        return findings
