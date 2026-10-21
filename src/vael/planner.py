import os
from .ai_engine import AIEngine

class Planner:
    def __init__(self):
        # Look for the GROQ_API_KEY environment variable. 
        # If it's not set, the tool safely defaults to deterministic mode.
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.ai = AIEngine(provider="groq", api_key=self.api_key)

    async def create_scan_plan(self, url: str) -> dict:
        print(f"[*] AI Brain is planning the attack for {url}...")
        
        custom_payload = await self.ai.mutate_payload(
            original_payload="<script>alert(1)</script>",
            context="<html><body><div>Search results for: [INJECT_HERE]</div></body></html>"
        )

        return {
            "run_headers": True,
            "run_cors": True,
            "run_csrf": True,
            "run_sensitive_files": True,
            "run_auth_bypass": True,
            "run_jwt": True,
            "run_api_fuzzer": True,
            "run_path_traversal": True,
            "run_xxe": True,
            "run_xss": True,
            "run_sqli": True,
            "custom_xss_payload": custom_payload
        }
