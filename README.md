# Domain 4 Security Toolkit

A Python CLI for firewall log analysis and incident response tracking — 
built to demonstrate the log-analysis and IR lifecycle skills tested by 
CompTIA Security+ Domain 4 (Security Operations and Monitoring).

## Features

### Log Analyzer
- **Brute force detection** — sliding-window threshold per (src, user)
- **Distributed brute force** — many sources, one target (botnet signature)
- **Port scan detection** — one source, many unique ports (recon)
- **Unusual port traffic** — anything outside your allow-list
- **Off-hours logins** — successful authentications outside business hours
- **Blocklist matching** — CIDR-aware, per-attacker aggregation
- **Live monitoring** — tail a log file, alert in real time with dedup
- **Visualizations** — timeline of failed logins, port distribution chart

### IR Tracker
- **Four lifecycle stages** hard-coded in NIST order (Preparation → 
  Detection/Analysis → Containment/Eradication/Recovery → Post-Incident)
- **Full CRUD** — create, load, update, close incidents with JSON persistence
- **Status + severity** — open/closed, low/medium/high/critical
- **Auto-populated incidents** — one command turns a log analysis into 
  a pre-filled incident
- **Evidence management** — attach files (PCAPs, screenshots, IOCs) with 
  stage tagging and copy-on-attach
- **Search & filter** — free-text across name/actions/notes; structured 
  filters by status/severity/date
- **Markdown export** — human-readable incident reports + bulk export
- **Dashboard** — aggregate metrics: open counts, severity distribution, 
  mean age

## Quick Start

```bash
git clone <repo-url>
cd domain4_tool
python3 -m venv .venv && source .venv/bin/activate
pip install matplotlib pytest

# Analyze a log file
python3 main.py analyze --log data/sample.log --blocklist data/blocklist.txt

# Analyze AND auto-open an IR incident
python3 main.py respond --log data/sample.log

# Launch the interactive IR tracker
python3 main.py ir

# Watch a log file in real time
python3 main.py watch --log data/sample.log --from-start