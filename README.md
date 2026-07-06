# SecurityOS v2.0 — Complete Security Recon Suite

🛡️ One Dashboard. Complete Security Recon. With VERIFIED Findings.

## Features

### Core Modules
1. **🔍 Subdomain Finder** — Discover all subdomains, IPs, and tech stack via certificate transparency
2. **🔑 Secret Scanner** — Find + VERIFY API keys, tokens, credentials with exploitability testing
3. **🔒 Header Checker** — Audit HTTP security headers with A-F grade
4. **📜 SSL Monitor** — Track SSL certificates and expiry dates
5. **🌑 Dark Web Monitor** — Monitor brand/email for breach data
6. **📸 Screenshot API** — Bulk website screenshots for reports

### Verification Engine
- Classifies secrets by type (GitHub PAT, AWS keys, Stripe, etc.)
- Context analysis (test vs prod, public vs private)
- Exploitability testing for actionable findings
- Risk scoring: P0 (Critical) → P4 (Info)
- FALSE POSITIVE detection — unlike competitors

## Deployment

### Option 1: Streamlit Cloud (FREE — Recommended)
```
1. Push to GitHub
2. Go to share.streamlit.io
3. Connect your repo
4. Deploy!
```

### Option 2: Local Run
```bash
cd securityos
pip install -r requirements.txt
streamlit run app.py
```

### Option 3: Vercel (Frontend Only)
Deploy the `landing/` folder separately for marketing site.

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| Free | ₹0 | 10 scans/day, basic reports |
| Hobbyist | ₹499/mo | 100 scans/day, PDF exports |
| Pro | ₹1,999/mo | Unlimited, API access, priority |
| Agency | ₹4,999/mo | Everything + white-label |

## Tech Stack

- **Frontend**: Streamlit (Python)
- **Database**: SQLite (free tier)
- **APIs**: crt.sh, GitHub API, urlscan.io, NVD
- **Hosting**: Streamlit Cloud (FREE)

## Verification Engine — How It Works

```
FIND → CLASSIFY → CONTEXT → EXPLOITABILITY → SCORE → REPORT
```

### Example:
- Input: `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` found in private repo
- Stage 1: ✅ DISCOVERED
- Stage 2: ✅ CLASSIFIED as GitHub PAT
- Stage 3: ✅ CONTEXT: private repo, production environment
- Stage 4: ✅ EXPLOITABILITY: Permissions = repo (full read/write)
- Stage 5: ✅ RISK SCORE: 92/100 → P0 CRITICAL
- Stage 6: ✅ VERIFIED REPORT with remediation steps

## License

© 2024 SecurityOS — All rights reserved