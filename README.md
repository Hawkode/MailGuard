# MailGuard

About the tool

MailGuard is a defensive email investigation CLI for analysing suspicious email files.

It extracts useful details from email headers, links, HTML content, attachments, authentication results, and Received headers. It also gives a risk score to help with manual phishing triage.

The tool does not open links, visit websites, download remote content, execute attachments, or upload email content anywhere.

Current features

- Analyse a single email file
- Scan a folder of email samples
- Extract common email headers
- Extract links from plain text and HTML
- Detect image URLs inside HTML emails
- List attachments
- Generate SHA256 hashes for attachments
- Extract IP addresses from Received headers
- Check SPF, DKIM, and DMARC results when present
- Detect Reply-To and Return-Path mismatches
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

Install the project:

```cmd
pip install -e .
```

Install test dependencies:

```cmd
pip install pytest
```

Check the CLI:

```cmd
mailguard --help
```

# Usage

Analyse one email file:

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

Alternative JSON command:

```cmd
.venv\Scripts\python.exe -m mailguard.cli analyze examples\suspicious.eml --json report.json
```

Scan a folder:

```cmd
mailguard scan-folder samples\spam\spam
```

Alternative folder scan command:

```cmd
.venv\Scripts\python.exe -m mailguard.cli scan-folder samples\spam\spam
```

Example single email output

```text
MailGuard Investigation Report

Risk score: 100/100
Verdict: High risk

Subject: Urgent invoice payment update
From: Antonio Cesare <giulio.cesare@example.co.uk>
Reply-To: Antonio Finance <antonio.cesare.finance@example.com>
Return-Path: <bounce@random-mailer.example>
Date: Thu, 02 Jul 2026 10:14:30 +0000
Message-ID: <123456789@random-mailer.example>

Received header IPs: 1

Received Header IPs

IP address      Scope
203.0.113.50    private

Findings:
- (+20) SPF failed
- (+15) DKIM missing
- (+25) DMARC failed
- (+20) Reply-To domain differs from From domain: example.com != example.co.uk
- (+15) Return-Path domain differs from From domain: random-mailer.example != example.co.uk
- (+5) Suspicious keyword found: invoice
- (+5) Suspicious keyword found: login
- (+5) Suspicious keyword found: payment
- (+5) Suspicious keyword found: reset
- (+5) Suspicious keyword found: urgent
- (+5) Suspicious link keyword found: reset
- (+5) Attachment found: invoice.pdf

Links found: 2

Extracted Links

1  https://example-payments.example-login.com/reset
2  https://tracking.example.com/open/12345.png

Attachments found: 1

Attachments

Filename     Content type       Size      SHA256
invoice.pdf  application/pdf    36 bytes  c51521e1bbbb827b40a051a05322f4d5cd2f0defea65925e0b1ab34ca32eb4f5
```

Example JSON report

```json
{
  "source_file": "examples\\suspicious.eml",
  "risk": {
    "score": 100,
    "verdict": "High risk"
  },
  "headers": {
    "subject": "Urgent invoice payment update",
    "from": "Antonio Cesare <giulio.cesare@example.co.uk>",
    "reply_to": "Antonio Finance <antonio.cesare.finance@example.com>",
    "return_path": "<bounce@random-mailer.example>",
    "date": "Thu, 02 Jul 2026 10:14:30 +0000",
    "message_id": "<123456789@random-mailer.example>"
  },
  "received_ips": [
    {
      "address": "203.0.113.50",
      "scope": "private"
    }
  ],
  "links": [
    "https://example-payments.example-login.com/reset",
    "https://tracking.example.com/open/12345.png"
  ],
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content_type": "application/pdf",
      "size_bytes": 36,
      "sha256": "c51521e1bbbb827b40a051a05322f4d5cd2f0defea65925e0b1ab34ca32eb4f5"
    }
  ]
}
```

Example folder scan output

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

# Next improvements

- Markdown report output
- CSV output for folder scans
- Better URL scoring
- Configurable rules
- GitHub Actions test workflow
- Optional reputation API checks

# Disclaimer

MailGuard highlights indicators that may help with manual email investigation. It does not prove that an email is safe or malicious.