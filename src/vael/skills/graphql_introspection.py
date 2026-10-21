import json
from ..http_engine import HTTPEngine

class GraphQLIntrospectionSkill:
    def __init__(self):
        self.name = "GraphQL Introspection"

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        test_url = f"{root_url}/graphql"
        
        # Standard GraphQL Introspection Query
        payload = {"query": "{__schema{types{name}}}"}
        headers = {"Content-Type": "application/json"}
        
        response = await engine.request("POST", test_url, data=json.dumps(payload), headers=headers)
        
        if response and response.status_code == 200:
            if "__schema" in response.text or "types" in response.text:
                findings.append({
                    "skill": self.name,
                    "target": test_url,
                    "issue": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "evidence": "The GraphQL endpoint allows introspection, leaking the entire API schema.",
                    "poc": f"Run this to dump the schema:\ncurl -X POST -H 'Content-Type: application/json' -d '{json.dumps(payload)}' {test_url}"
                })
        return findings
