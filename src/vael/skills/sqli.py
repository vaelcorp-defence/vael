import urllib.parse
from ..http_engine import HTTPEngine

class SQLiSkill:
    def __init__(self):
        self.name = "SQL Injection (Error & Boolean)"
        self.payloads = [
            ("'", "error"), 
            ("' OR 1=1--", "boolean"),
            ("\" OR 1=1--", "boolean")
        ]
        self.error_signatures = [
            "SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL",
            "SQLite/JDBCDriver", "Unclosed quotation mark", "You have an error"
        ]

    def _check_for_errors(self, text: str) -> str:
        for signature in self.error_signatures:
            if signature.lower() in text.lower():
                return signature
        return None

    async def run(self, target: dict, engine: HTTPEngine) -> list:
        findings = []
        url = target["url"]
        method = target["method"]
        params = target["params"].copy()

        # --- HANDLE GET REQUESTS ---
        if method == "GET":
            parsed = urllib.parse.urlparse(url)
            url_params = urllib.parse.parse_qs(parsed.query)
            
            if not url_params:
                return findings

            for param_name in url_params:
                # Get the baseline response
                baseline_url = url
                baseline_resp = await engine.request("GET", baseline_url)
                if not baseline_resp:
                    continue
                baseline_len = len(baseline_resp.text)

                for payload, payload_type in self.payloads:
                    test_params = url_params.copy()
                    original_value = url_params[param_name][0]
                    
                    # For boolean, we append to the original value. For error, we just append the quote.
                    if payload_type == "boolean":
                        test_params[param_name] = [f"{original_value} {payload}"]
                    else:
                        test_params[param_name] = [f"{original_value}{payload}"]
                    
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                    response = await engine.request("GET", test_url)
                    
                    if not response: continue

                    # 1. Check Error-Based
                    error_found = self._check_for_errors(response.text)
                    if not error_found and response.status_code == 500:
                        error_found = f"HTTP 500 triggered by payload '{payload}'"

                    # 2. Check Boolean-Based (If response size changes drastically)
                    if payload_type == "boolean" and abs(len(response.text) - baseline_len) > 100:
                         error_found = f"Boolean-based response difference (Baseline: {baseline_len} bytes, Injected: {len(response.text)} bytes)"

                    if error_found:
                        poc = f"Open this URL in a browser to verify:\n{test_url}"
                        findings.append({
                            "skill": self.name,
                            "target": test_url,
                            "issue": f"SQL Injection in parameter '{param_name}' (GET)",
                            "severity": "Critical",
                            "evidence": error_found,
                            "poc": poc
                        })
                        break # Move to next parameter
        return findings
