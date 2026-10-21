# Vaelcorp Defence (v0.0.5)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)
![Status](https://img.shields.io/badge/Status-Beta-orange.svg)

**An autonomous, AI-assisted web application vulnerability research agent.**

Vaelcorp Defence is designed for bug bounty hunters, penetration testers, and security researchers who demand deterministic, evidence-backed findings with zero false positives. It is built to find the bugs that actually pay.

## 🚀 Core Features

*   **30+ Built-in Vulnerability Skills:**
    *   Security Headers & CORS Misconfigurations
    *   Reflected XSS & DOM-Based XSS (via Playwright)
    *   Error & Boolean-Based SQL Injection (GET & POST)
    *   Insecure Direct Object Reference (IDOR) - *Requires Two Sessions*
    *   Forced API Browsing & Unauthenticated Data Leaks
    *   JWT Privilege Escalation (alg:none & Weak Secrets)
    *   Path Traversal / Local File Inclusion (LFI)
    *   CSRF Misconfigurations
    *   XXE / Unrestricted File Upload
    *   Open Redirects & Sensitive File Discovery
    *   SSRF (Server-Side Request Forgery)
    *   Host Header Injection
    *   HTML Injection
    *   GraphQL Introspection
    *   Framework & Config Exposure (Spring Boot, Laravel, Django, etc.)
    *   JavaScript Secret Scanner (AWS, Google Maps, Stripe, etc.)
    *   Vulnerable JS Libraries
*   **Dual Crawling Engines:** Standard HTML parsing (BeautifulSoup) for speed, and a Stealth JavaScript crawler (Playwright) for React/Vue/Angular applications. Includes CAPTCHA/WAF evasion using visible browser contexts.
*   **AI-Assisted WAF Evasion:** Uses Groq (Llama 3) to dynamically mutate payloads when a Web Application Firewall blocks the default ones.
*   **Two-Session IDOR Engine:** Supply two different user cookies to mathematically prove Broken Access Control by extracting User A's email from their JWT and searching for it in User B's response.
*   **Proof-of-Concept (PoC) Generation:** Automatically generates exact `curl` commands and browser URLs so you can reproduce bugs instantly.
*   **Persistent Database & Reports:** Saves findings to SQLite and generates beautiful Markdown and dark-mode HTML reports.

## 🛠️ Installation

Requires **Python 3.12+** and **Kali Linux** (or any Debian-based distro).

```bash
# Clone the repository
git clone https://github.com/vaelcorp-defence/vael.git
cd vael

# Setup Virtual Environment (Required)
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install -e .

# Install Playwright Browser (Required for --js mode)
playwright install chromium

# Initialize Vaelcorp
vael init
```

## 🧠 Activating the AI Brain (Optional)

Vaelcorp uses Groq's API for AI-driven WAF evasion and payload generation. You can get a **100% free API key** at [console.groq.com](https://console.groq.com).

To activate the AI, export your key in the terminal before running a scan:
```bash
export GROQ_API_KEY="gsk_your_api_key_here"
```
*Note: If no key is provided, Vaelcorp will seamlessly fall back to its deterministic payload engine and still function perfectly.*

## 🎯 Usage

**Basic Scan (HTML):**
```bash
vael scan -t "https://example.com" -p safe
```

**JavaScript Scan (React/Vue/Angular):**
```bash
vael scan -t "https://example.com" -p safe --js
```

**Authenticated Scan (Behind a Login):**
```bash
vael scan -t "https://example.com" -p safe --cookie "PHPSESSID=abc123"
```

**Two-Session IDOR Check:**
```bash
vael scan -t "https://example.com" -p safe --cookie "session=userA" --cookie2 "session=userB"
```

**Bearer Token / API Scan (Supabase, etc.):**
```bash
vael scan -t "https://api.example.com" --bearer "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**View Findings & Reports:**
```bash
# View the top 50 recent findings in the terminal
vael findings

# View available skills
vael skills
```

## 📁 Output
All findings are saved to a local SQLite database (`vael.db`).
Reports are saved in the `/reports` directory as both Markdown and a dark-mode HTML dashboard.

## ⚖️ Disclaimer
This tool is for **authorized security testing and educational purposes only**. Do not use Vaelcorp against targets without explicit, written permission from the system owner. The creators (Vaelcorp Defence) assume no liability for misuse or damage caused by this program.

---
*Built by Vaelcorp Defence. Stay stealthy.*
