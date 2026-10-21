import httpx

class AIEngine:
    def __init__(self, provider: str = "groq", api_key: str = None, model: str = "openai/gpt-oss-20b"):
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    async def mutate_payload(self, original_payload: str, context: str = "") -> str:
        """
        Asks the Groq API to generate a new payload if the original one failed or was blocked.
        """
        if not self.api_key:
            return original_payload

        prompt = f"""
        You are an elite web security researcher.
        My XSS payload '{original_payload}' was blocked or failed.
        The HTML context where it reflected is: {context}
        Generate ONE new evasive XSS payload that fits this HTML context and bypasses common WAFs.
        Do NOT include markdown formatting, code blocks, or any explanations. 
        Just output the raw payload string.
        """
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.base_url, headers=headers, json=data)
                
                if resp.status_code != 200:
                    print(f"    [AI ERROR] Groq returned status {resp.status_code}: {resp.text}")
                    return original_payload
                    
                result = resp.json()
                payload = result["choices"][0]["message"]["content"].strip()
                
                # Clean up in case the AI adds markdown code blocks or quotes
                payload = payload.replace("```html", "").replace("```", "").replace('"', '').strip()
                
                if payload:
                    print(f"    [AI] Generated new payload: {payload}")
                    return payload
                return original_payload
                
        except Exception as e:
            print(f"    [AI ERROR] Could not connect to Groq: {e}")
            return original_payload
