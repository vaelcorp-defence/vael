import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import html

class ReportGenerator:
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.scan_id = f"scan_{self.timestamp}"

    def generate(self, findings: List[Dict], format: str = "markdown"):
        output_dir = Path("./reports")
        output_dir.mkdir(exist_ok=True)
        
        deduped_findings = {}
        for f in findings:
            issue_name = f['issue']
            if issue_name not in deduped_findings:
                deduped_findings[issue_name] = f.copy()
                deduped_findings[issue_name]['affected_urls'] = [f['target']]
            else:
                deduped_findings[issue_name]['affected_urls'].append(f['target'])
        
        unique_findings = list(deduped_findings.values())

        if format == "json":
            file_path = output_dir / f"{self.scan_id}.json"
            report_data = {
                "scan_id": self.scan_id,
                "target": self.target,
                "timestamp": self.timestamp,
                "total_unique_findings": len(unique_findings),
                "findings": unique_findings
            }
            file_path.write_text(json.dumps(report_data, indent=4))
            
        else:
            file_path = output_dir / f"{self.scan_id}.md"
            
            md_content = f"# Vaelcorp Defence - Scan Report\n\n"
            md_content += f"**Target:** {self.target}\n"
            md_content += f"**Date:** {self.timestamp}\n"
            md_content += f"**Total Unique Findings:** {len(unique_findings)}\n\n"
            md_content += "## Findings\n\n"
            
            if not unique_findings:
                md_content += "No vulnerabilities found.\n"
            else:
                for i, f in enumerate(unique_findings, 1):
                    md_content += f"### {i}. {f['issue']}\n"
                    md_content += f"- **Severity:** {f['severity']}\n"
                    md_content += f"- **Skill:** {f['skill']}\n"
                    md_content += f"- **Affected URLs:**\n"
                    for url in f['affected_urls']:
                        md_content += f"  - {url}\n"
                    md_content += f"- **Evidence:** {f['evidence']}\n"
                    if 'poc' in f:
                        md_content += f"- **Proof of Concept:**\n```\n{f['poc']}\n```\n"
                    md_content += "\n"
            
            file_path.write_text(md_content)

        return file_path

    def generate_html(self, unique_findings: list):
        output_dir = Path("./reports")
        file_path = output_dir / f"{self.scan_id}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vaelcorp Defence - Report</title>
            <style>
                body {{ background-color: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 20px; }}
                h1 {{ color: #ff4444; border-bottom: 2px solid #333; padding-bottom: 10px; }}
                .finding {{ background: #1e1e1e; border-left: 4px solid #ff4444; margin-bottom: 20px; padding: 15px; border-radius: 4px; }}
                .High {{ border-left-color: #ff4444; }}
                .Medium {{ border-left-color: #ffaa00; }}
                .Low {{ border-left-color: #00aaff; }}
                .badge {{ padding: 3px 8px; border-radius: 3px; font-weight: bold; font-size: 0.8em; }}
                .bg-High {{ background: #ff4444; color: #fff; }}
                .bg-Medium {{ background: #ffaa00; color: #000; }}
                .bg-Low {{ background: #00aaff; color: #fff; }}
                pre {{ background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; color: #00ff00; }}
                .url-list {{ list-style-type: none; padding-left: 0; color: #888; }}
            </style>
        </head>
        <body>
            <h1>Vaelcorp Defence - Scan Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Date:</strong> {self.timestamp}</p>
            <p><strong>Total Unique Findings:</strong> {len(unique_findings)}</p>
            <hr style="border-color: #333;">
        """
        
        for i, f in enumerate(unique_findings, 1):
            html_content += f"""
            <div class="finding {f['severity']}">
                <h3><span class="badge bg-{f['severity']}">{f['severity']}</span> {i}. {html.escape(f['issue'])}</h3>
                <p><strong>Skill:</strong> {f['skill']}</p>
                <p><strong>Evidence:</strong> {html.escape(f['evidence'])}</p>
            """
            
            if 'poc' in f:
                html_content += f"<p><strong>Proof of Concept:</strong></p><pre>{html.escape(f['poc'])}</pre>"
                
            html_content += "<p><strong>Affected URLs:</strong></p><ul class='url-list'>"
            for url in f['affected_urls']:
                html_content += f"<li>{html.escape(url)}</li>"
            html_content += "</ul></div>"
            
        html_content += "</body></html>"
        file_path.write_text(html_content)
        return file_path
