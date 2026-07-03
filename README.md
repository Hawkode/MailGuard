# MailGuard

About the tool

MailGuard is a defensive email investigation CLI for analysing suspicious email files.

It extracts useful details from email headers, links, HTML content, attachments, authentication results, and received headers. It also gives a risk score to help with manual phishing triage.

The tool does not open links, visit websites, download remote content, execute attachments, or upload email content anywhere.

Current features

- Analyse a single email file
- Scan a folder of email samples
- Extract common headers
- Extract links from plain text and HTML
- Detect image URLs inside HTML emails
- List attachments
- Generate SHA256 hashes for attachments
- Extract IP addresses from Received headers
- Check SPF, DKIM, and DMARC results when present
- Detect sender mismatch indicators
- Detect suspicious keywords
- Generate terminal reports
- Generate JSON reports
- Skip files that do not look like emails during folder scans

# Installation

Clone the repository:

```cmd
git clone https://github.com/Hawkode/MailGuard.git
cd MailGuard
```

Create a virtual environment:

```cmd
py -m venv .venv
```

Activate it:

```cmd
.venv\Scripts\activate
```

Install the tool:

```cmd
pip install -e .
```

Install test dependencies:

```cmd
pip install pytest
```

Check the tool:

```cmd
mailguard --help
```

# Usage

Analyse the included sample email:

```cmd
mailguard analyze examples\suspicious.eml
```

Alternative command:

```cmd
.venv\Scripts\python.exe -m mailguard.cli analyze examples\suspicious.eml
```

Create a JSON report:

```cmd
mailguard analyze examples\suspicious.eml --json report.json
```

Scan a folder:

```cmd
mailguard scan-folder samples\spam\spam
```

Alternative folder scan command:

```cmd
.venv\Scripts\python.exe -m mailguard.cli scan-folder samples\spam\spam
```

Example single email output:

```text
MailGuard Investigation Report

Risk score: 95/100
Verdict: High risk

Subject: Urgent invoice payment update
From: Giulio Cesare <giulio.cesare@example.co.uk>
Reply-To: Antonio Finance <antonio.cesare.finance@example.com>
Return-Path: <bounce@random-mailer.example>
Date: Tue, 2 Jul 2026 10:14:30 +0000
Message-ID: <123456789@random-mailer.example>

Received header IPs: 1

Findings:
- SPF failed
- DKIM missing
- DMARC failed
- Reply-To domain differs from From domain
- Suspicious keyword found: urgent

Links found: 2
Attachments found: 1
```

Example folder scan output:

```text
MailGuard Folder Scan Summary

Scanned: 499
High risk: 120
Suspicious: 230
Low risk: 149
Skipped: 1
Errors: 0
```

# Testing

Run tests:

```cmd
.venv\Scripts\python.exe -m pytest
```

Local files

The repository does not include virtual environments, cache files, generated reports, or downloaded datasets.

Ignored local paths:

```text
.venv/
.pytest_cache/
__pycache__/
mailguard.egg-info/
datasets/
samples/
reports/
report.json
```

The repository includes one synthetic sample email:

```text
examples/suspicious.eml
```

Do not commit real emails, private reports, API keys, personal data, or downloaded phishing/spam datasets.

Project structure

```text
MailGuard/
├── examples/
│   └── suspicious.eml
├── mailguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── folder_scan.py
│   ├── headers.py
│   ├── json_report.py
│   ├── parser.py
│   ├── report.py
│   └── scoring.py
├── tests/
│   └── test_parser.py
├── .gitignore
├── README.md
└── pyproject.toml
```

Roadmap

- Markdown report output
- CSV output for folder scans
- Better URL scoring
- Configurable rules
- GitHub Actions test workflow
- Optional reputation API checks

Disclaimer

MailGuard highlights indicators that may help with manual email investigation. It does not prove that an email is safe or malicious.