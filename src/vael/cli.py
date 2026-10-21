import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from .config import VaelConfig
from .database import init_db, save_findings, get_findings, clear_findings

console = Console()

def print_banner():
    """Prints a massive, professional ASCII banner for Vaelcorp."""
    banner_text = r"""
[bold cyan]
 ██╗   ██╗ █████╗ ███████╗██╗     
 ██║   ██║██╔══██╗██╔════╝██║     
 ██║   ██║███████║█████╗  ██║     
 ╚██╗ ██╔╝██╔══██║██╔══╝  ██║     
  ╚████╔╝ ██║  ██║███████╗███████╗
   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚══════╝
[/bold cyan]
[bold red]     Vaelcorp Defence - Autonomous Vulnerability Research[/bold red]
[dim]                 Version 0.0.5 | Bounty Hunter Release[/dim]
    """
    console.print(Align.center(banner_text))

app = typer.Typer(
    name="vael",
    help="Autonomous web application vulnerability research agent by Vaelcorp Defence.",
    no_args_is_help=False,
)

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Vaelcorp Defence Main Entry Point."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(Align.center("[dim]Run [bold green]vael --help[/bold green] to see available commands.[/dim]\n"))
        # Print the standard help menu below the banner
        with console.capture() as capture:
            console.print(ctx.get_help())
        console.print(capture.get())

@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config file.")
):
    """Initialize a new Vael configuration file."""
    print_banner()
    config_path = Path("vael.toml")
    
    if config_path.exists() and not force:
        typer.echo("Error: vael.toml already exists. Use --force to overwrite.", err=True)
        raise typer.Exit(code=1)
        
    default_config = VaelConfig()
    
    toml_content = f"""[scope]
targets = []
allow_subdomains = false

[scan]
profile = "{default_config.scan.profile}"
max_requests = {default_config.scan.max_requests}
timeout_seconds = {default_config.scan.timeout_seconds}

[ai]
enabled = {str(default_config.ai.enabled).lower()}
provider = "{default_config.ai.provider}"
model = ""

[report]
format = "{default_config.report.format}"
output_dir = "{default_config.report.output_dir}"
"""
    
    config_path.write_text(toml_content)
    init_db()
    console.print(f"[bold green][+][/bold green] Created {config_path.absolute()}")
    console.print("[bold green][+][/bold green] Database initialized.")
    console.print("[bold green][+][/bold green] Configuration initialized successfully.")

@app.command()
def scan(
    target: str = typer.Option(None, "--target", "-t", help="The authorized URL to scan."),
    profile: str = typer.Option("passive", "--profile", "-p", help="Scan profile: passive, safe, advanced."),
    js: bool = typer.Option(False, "--js", help="Use headless Chrome for JavaScript-heavy sites."),
    cookie: str = typer.Option(None, "--cookie", "-c", help="Session cookie for authenticated scans."),
    cookie2: str = typer.Option(None, "--cookie2", "-c2", help="Session cookie for a second user (User B) for IDOR checks."),
    bearer: str = typer.Option(None, "--bearer", "-b", help="Bearer token for API authentication (Supabase, etc).")
):
    """Run a scan against a target."""
    print_banner()
    if not target:
        target = typer.prompt("Enter the target URL to scan (e.g., https://example.com)")
        
    if not target.startswith("http"):
        typer.echo("Error: Target must start with http:// or https://", err=True)
        raise typer.Exit(code=1)

    # --- INTERACTIVE SESSION MANAGER ---
    if not cookie and not bearer:
        try:
            import httpx
            console.print(f"[bold blue][*][/bold blue] Pre-flight check: Testing authentication...")
            temp_resp = httpx.get(target, follow_redirects=False, timeout=5, verify=False)
            
            if temp_resp.status_code in [401, 403] or (temp_resp.is_redirect and "login" in temp_resp.headers.get("location", "").lower()):
                console.print("[bold yellow][!] Target appears to require authentication.[/bold yellow]")
                cookie = typer.prompt("Paste your session cookie (or press Enter to continue as guest)", default="", show_default=False)
                if not cookie:
                    cookie = None
        except Exception:
            pass

    typer.echo(f"Starting scan against {target} using profile: {profile}")
    
    import asyncio
    from .scope import ScopeManager
    from .http_engine import HTTPEngine
    from .crawler import Crawler
    from .planner import Planner
    from .skills.headers import SecurityHeadersSkill
    from .skills.xss import XSSSkill
    from .skills.sqli import SQLiSkill
    from .skills.cors import CORSSkill
    from .skills.sensitive_files import SensitiveFilesSkill
    from .skills.auth_bypass import AuthBypassSkill
    from .skills.idor import IDORSkill
    from .skills.open_redirect import OpenRedirectSkill
    from .skills.dom_xss import DOMXSSSkill
    from .skills.api_injection import APIInjectionSkill
    from .skills.jwt_attack import JWTAttackSkill
    from .skills.api_fuzzer import APIFuzzerSkill
    from .skills.api_param_fuzzer import APIParamFuzzerSkill
    from .skills.api_wordlist import APIWordlistSkill
    from .skills.path_traversal import PathTraversalSkill
    from .skills.csrf import CSRFSkill
    from .skills.xxe_upload import XXEUploadSkill
    from .skills.js_secrets import JSSecretScanner
    from .skills.directory_bruteforce import DirectoryBruteforceSkill
    from .skills.http_methods import HTTPMethodSkill
    from .skills.server_banner import ServerBannerSkill
    from .skills.vuln_js import VulnJSSkill
    from .skills.header_xss import HeaderXSSSkill
    from .skills.graphql_introspection import GraphQLIntrospectionSkill
    from .skills.cors_wildcard import CORSWildcardSkill
    from .skills.ssrf import SSRFSkill
    from .skills.host_header import HostHeaderSkill
    from .skills.html_injection import HTMLInjectionSkill
    from .skills.framework_files import FrameworkFilesSkill
    from .report import ReportGenerator

    init_db()

    async def run_scan():
        scope = ScopeManager([target])
        engine = HTTPEngine(scope, cookie_string=cookie, bearer_token=bearer)
        
        engine_user_b = None
        if cookie2:
            console.print("[bold magenta][*][/bold magenta] Second session cookie provided. Enabling Two-Session IDOR checks.")
            engine_user_b = HTTPEngine(scope, cookie_string=cookie2)
        
        # 1. Crawl
        if js:
            from .js_crawler import JSCrawler
            console.print(f"[bold blue][*][/bold blue] Starting JS (Playwright) Crawler against [cyan]{target}[/cyan]...")
            crawler = JSCrawler(scope, cookie_string=cookie)
            await crawler.crawl(target, max_pages=5)
        else:
            console.print(f"[bold blue][*][/bold blue] Starting HTML Crawler against [cyan]{target}[/cyan]...")
            crawler = Crawler(engine)
            await crawler.crawl(target, max_pages=5)
        
        # 2. AI Planning
        planner = Planner()
        plan = await planner.create_scan_plan(target)
        console.print(f"[bold magenta][*][/bold magenta] AI Plan Generated: {plan}")
        
        # 3. Setup Skills
        console.print(f"[bold blue][*][/bold blue] Crawled {len(crawler.found_urls)} pages. Running checks...")
        
        headers_skill = SecurityHeadersSkill()
        xss_skill = XSSSkill()
        sqli_skill = SQLiSkill()
        cors_skill = CORSSkill()
        files_skill = SensitiveFilesSkill()
        auth_skill = AuthBypassSkill()
        idor_skill = IDORSkill()
        redirect_skill = OpenRedirectSkill()
        dom_xss_skill = DOMXSSSkill()
        api_inject_skill = APIInjectionSkill()
        jwt_skill = JWTAttackSkill()
        api_fuzzer_skill = APIFuzzerSkill()
        api_param_skill = APIParamFuzzerSkill()
        api_wordlist_skill = APIWordlistSkill()
        path_traversal_skill = PathTraversalSkill()
        csrf_skill = CSRFSkill()
        xxe_skill = XXEUploadSkill()
        js_secrets_skill = JSSecretScanner()
        dir_brute_skill = DirectoryBruteforceSkill()
        http_methods_skill = HTTPMethodSkill()
        banner_skill = ServerBannerSkill()
        vuln_js_skill = VulnJSSkill()
        header_xss_skill = HeaderXSSSkill()
        graphql_skill = GraphQLIntrospectionSkill()
        cors_wildcard_skill = CORSWildcardSkill()
        ssrf_skill = SSRFSkill()
        host_skill = HostHeaderSkill()
        html_inj_skill = HTMLInjectionSkill()
        framework_skill = FrameworkFilesSkill()
        
        all_findings = []
        
        # 4. Execute based on AI Plan
        if plan.get("run_headers") or plan.get("run_cors"):
            for url in crawler.found_urls:
                if plan.get("run_headers"):
                    findings = await headers_skill.run(url, engine)
                    all_findings.extend(findings)
                
                if plan.get("run_cors"):
                    findings = await cors_skill.run(url, engine)
                    all_findings.extend(findings)

                if plan.get("run_csrf"):
                    findings = await csrf_skill.run(url, engine)
                    all_findings.extend(findings)
            
        if plan.get("run_sensitive_files"):
            console.print(f"[bold blue][*][/bold blue] Testing for exposed sensitive files...")
            findings = await files_skill.run(target, engine)
            all_findings.extend(findings)

        if plan.get("run_auth_bypass"):
            console.print(f"[bold blue][*][/bold blue] Testing for Auth Bypass (Force Browsing)...")
            findings = await auth_skill.run(target, engine)
            all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Testing for HTTP Method Tampering...")
        findings = await http_methods_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Grabbing Server Banners...")
        findings = await banner_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Testing for GraphQL Introspection...")
        findings = await graphql_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Testing for Host Header Injection...")
        findings = await host_skill.run(target, engine)
        all_findings.extend(findings)

        if plan.get("run_jwt") and cookie:
            console.print(f"[bold blue][*][/bold blue] Testing for JWT Privilege Escalation (alg:none)...")
            findings = await jwt_skill.run(target, engine, cookie)
            all_findings.extend(findings)

        if plan.get("run_api_fuzzer"):
            console.print(f"[bold blue][*][/bold blue] Running Forced API Browsing & IDOR checks...")
            findings = await api_fuzzer_skill.run(target, engine, engine_user_b)
            all_findings.extend(findings)

            console.print(f"[bold blue][*][/bold blue] Running Directory Bruteforce...")
            findings = await dir_brute_skill.run(target, engine)
            all_findings.extend(findings)

            console.print(f"[bold blue][*][/bold blue] Scanning for Framework & Config Exposure...")
            findings = await framework_skill.run(target, engine)
            all_findings.extend(findings)

            console.print(f"[bold blue][*][/bold blue] Running API Parameter Fuzzer...")
            findings = await api_param_skill.run(target, engine)
            all_findings.extend(findings)

            console.print(f"[bold blue][*][/bold blue] Running API Wordlist Fuzzer...")
            findings = await api_wordlist_skill.run(target, engine, engine_user_b)
            all_findings.extend(findings)

        if plan.get("run_path_traversal"):
            console.print(f"[bold blue][*][/bold blue] Testing for Path Traversal (LFI)...")
            findings = await path_traversal_skill.run(target, engine)
            all_findings.extend(findings)

        if plan.get("run_xxe"):
            console.print(f"[bold blue][*][/bold blue] Testing for XXE / File Upload...")
            findings = await xxe_skill.run(target, engine)
            all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Scanning JavaScript files for exposed secrets...")
        findings = await js_secrets_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Scanning for Vulnerable JS Libraries...")
        findings = await vuln_js_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Testing for HTTP Header XSS...")
        findings = await header_xss_skill.run(target, engine)
        all_findings.extend(findings)

        console.print(f"[bold blue][*][/bold blue] Testing for CORS Wildcard...")
        for url in crawler.found_urls:
            findings = await cors_wildcard_skill.run(url, engine)
            all_findings.extend(findings)

        # --- FORCE LOGIN BYPASS TEST ---
        console.print(f"[bold blue][*][/bold blue] Testing for Authentication Bypass (JSON SQLi)...")
        root_target_dict = {"url": target, "method": "GET", "params": {}}
        findings = await api_inject_skill.run(root_target_dict, engine)
        all_findings.extend(findings)
        # -------------------------------

        # Run DOM XSS on all found URLs (only if --js is enabled)
        if js and plan.get("run_xss"):
            console.print(f"[bold blue][*][/bold blue] Running DOM XSS checks on {len(crawler.found_urls)} pages...")
            for url in crawler.found_urls:
                findings = await dom_xss_skill.run(url, engine, cookie)
                all_findings.extend(findings)
            
        if plan.get("run_xss") or plan.get("run_sqli"):
            seen = set()
            unique_targets = []
            for t in crawler.vulnerable_targets:
                key = (t['url'], t['method'], str(t['params']))
                if key not in seen:
                    seen.add(key)
                    unique_targets.append(t)

            console.print(f"[bold blue][*][/bold blue] Found {len(unique_targets)} parameterized targets (GET/POST/API). Running Parameter Checks...")
            
            for t in unique_targets:
                if plan.get("run_xss"):
                    ai_payload = plan.get("custom_xss_payload")
                    findings = await xss_skill.run(t, engine, custom_payload=ai_payload)
                    all_findings.extend(findings)
                
                if plan.get("run_sqli"):
                    findings = await sqli_skill.run(t, engine)
                    all_findings.extend(findings)

                findings = await api_inject_skill.run(t, engine)
                all_findings.extend(findings)

                # Pass cookie to IDOR for the email extraction logic
                findings = await idor_skill.run(t, engine, engine_user_b, cookie)
                all_findings.extend(findings)

                findings = await redirect_skill.run(t, engine)
                all_findings.extend(findings)

                findings = await html_inj_skill.run(t, engine)
                all_findings.extend(findings)

                findings = await ssrf_skill.run(t, engine)
                all_findings.extend(findings)
            
        await engine.close()
        if engine_user_b:
            await engine_user_b.close()
        
        # 5. Print Results (Rich Table)
        table = Table(title="Vaelcorp Defence - Scan Summary")
        table.add_column("Severity", style="bold red", no_wrap=True)
        table.add_column("Issue", style="white")
        table.add_column("Affected URLs", style="cyan")
        
        severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
        sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x['severity'], 6))
        
        dedup = {}
        for f in sorted_findings:
            if f['issue'] not in dedup:
                dedup[f['issue']] = {"sev": f['severity'], "count": 1}
            else:
                dedup[f['issue']]["count"] += 1
                
        for issue, data in dedup.items():
            table.add_row(data['sev'], issue, str(data['count']))
            
        console.print("\n")
        console.print(table)
            
        # 6. Generate Report & Save to DB
        reporter = ReportGenerator(target)
        md_path = reporter.generate(all_findings, format="markdown")
        
        deduped = {}
        for f in all_findings:
            issue_name = f['issue']
            if issue_name not in deduped:
                deduped[issue_name] = f.copy()
                deduped[issue_name]['affected_urls'] = [f['target']]
            else:
                deduped[issue_name]['affected_urls'].append(f['target'])
        unique_findings = list(deduped.values())
        
        html_path = reporter.generate_html(unique_findings)
        
        console.print(f"\n[bold green][+][/bold green] Markdown Report saved to: [underline]{md_path.absolute()}[/underline]")
        console.print(f"[bold green][+][/bold green] HTML Report saved to: [underline]{html_path.absolute()}[/underline]")
        
        save_findings(reporter.scan_id, target, all_findings)
        console.print(f"[bold green][+][/bold green] Findings saved to database ({len(all_findings)} records).")

    asyncio.run(run_scan())

@app.command("clear")
def clear_db():
    """Clear all findings from the database."""
    print_banner()
    clear_findings()
    typer.echo("Database cleared successfully.")

@app.command("findings")
def list_findings(
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by severity (e.g., High, Medium).")
):
    """List findings from previous scans."""
    print_banner()
    init_db()
    rows = get_findings(status)
    
    if not rows:
        typer.echo("No findings found in the database.")
        return

    table = Table(title="Vaelcorp Defence - Saved Findings")
    table.add_column("Target", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Issue", style="white")
    table.add_column("PoC", style="green")

    for row in rows:
        target, severity, issue, url, poc, skill = row
        table.add_row(target, severity, issue, poc)

    console.print(table)

@app.command("skills")
def list_skills():
    """List installed testing skills."""
    print_banner()
    console.print("[bold cyan]Available Skills:[/bold cyan]")
    typer.echo("- Security Headers")
    typer.echo("- Reflected XSS & DOM XSS")
    typer.echo("- Error & Boolean-Based SQLi (GET & POST)")
    typer.echo("- CORS Misconfiguration & CORS Wildcard")
    typer.echo("- Sensitive File Discovery")
    typer.echo("- Auth Bypass (Force Browsing)")
    typer.echo("- IDOR (Insecure Direct Object Reference)")
    typer.echo("- Open Redirect")
    typer.echo("- API JSON Injection (Login Bypass)")
    typer.echo("- JWT Privilege Escalation (alg:none)")
    typer.echo("- Forced API Browsing & IDOR")
    typer.echo("- API Parameter Fuzzer")
    typer.echo("- API Wordlist Fuzzer")
    typer.echo("- Path Traversal / LFI")
    typer.echo("- CSRF (Cross-Site Request Forgery)")
    typer.echo("- XXE / File Upload")
    typer.echo("- JavaScript Secret Scanner")
    typer.echo("- Directory Bruteforce")
    typer.echo("- HTTP Method Tampering")
    typer.echo("- Server Banner Grabbing")
    typer.echo("- Vulnerable JS Library")
    typer.echo("- HTTP Header XSS")
    typer.echo("- GraphQL Introspection")
    typer.echo("- SSRF (Server-Side Request Forgery)")
    typer.echo("- Host Header Injection")
    typer.echo("- HTML Injection")
    typer.echo("- Framework & Config Exposure")

@app.command()
def report(
    latest: bool = typer.Option(False, "--latest", help="Generate report for the latest scan."),
    format: str = typer.Option("html", "--format", "-f", help="Report format: json, md, html.")
):
    """Generate a report for a scan."""
    print_banner()
    typer.echo(f"Generating report (format: {format}, latest: {latest})")
    typer.echo("[Not implemented yet] - Report generation logic goes here.")

if __name__ == "__main__":
    app()
