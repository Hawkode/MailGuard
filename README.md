# MailGuard

MailGuard is a defensive email investigation CLI for analysing suspicious `.eml` files.

It extracts useful details from email headers, links, HTML content, and attachments. The tool is designed for safe phishing triage and does not open links, download remote content, or execute attachments.

Status

This project is in early development.

Current version includes:

- `.eml` file parsing
- Sender header extraction
- Link extraction from text and HTML
- Image URL detection from HTML
- Attachment listing
- Terminal report output
- Synthetic sample email
- Basic pytest coverage

Planned features:

- Risk scoring
- SPF, DKIM, and DMARC checks
- Sender IP extraction from `Received` headers
- Suspicious keyword detection
- URL risk analysis
- Attachment hashing
- JSON report output
- Markdown report output
- GitHub Actions workflow

Features

MailGuard currently extracts:

- `From`
- `Reply-To`
- `Return-Path`
- `Date`
- `Message-ID`
- Links from plain text email bodies
- Links from HTML email bodies
- Image URLs from HTML emails
- Attachment filename
- Attachment content type
- Attachment size

Installation

Clone the repository:

```cmd
git clone https://github.com/Hawkode/MailGuard.git
cd MailGuard
```

Create a virtual environment:

```cmd
py -m venv .venv
```

Activate the virtual environment:

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

Usage

Analyse the included sample email:

```cmd
mailguard analyze examples\suspicious.eml
```

Alternative command:

```cmd
.venv\Scripts\python.exe -m mailguard.cli analyze examples\suspicious.eml
```

Example output:

```text
MailGuard Investigation Report

Subject: Urgent invoice payment update
From: Giulio Cesare <giulio.cesare@example.co.uk>
Reply-To: Antonio Finance <antonio.cesare.finance@example.com>
Return-Path: <bounce@random-mailer.example>
Date: Tue, 2 Jul 2026 10:14:30 +0000
Message-ID: <123456789@random-mailer.example>

Links found: 2
Attachments found: 1
```

Testing

Run the test suite:

```cmd
.venv\Scripts\python.exe -m pytest
```

Expected result:

```text
1 passed
```

Project structure

```text
mailguard/
├── mailguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── parser.py
│   └── report.py
├── tests/
│   └── test_parser.py
├── examples/
│   └── suspicious.eml
├── README.md
├── pyproject.toml
└── .gitignore
```

Safety

MailGuard does not:

- Open URLs
- Visit websites
- Download remote images
- Execute attachments
- Upload email content anywhere

Only synthetic sample emails should be committed to this repository.

Do not commit:

- Real emails
- Private reports
- API keys
- Personal data
- Live investigation files

Troubleshooting

If `mailguard` is not recognised, use:

```cmd
.venv\Scripts\python.exe -m mailguard.cli analyze examples\suspicious.eml
```

If tests do not run, install pytest again:

```cmd
.venv\Scripts\python.exe -m pip install pytest
.venv\Scripts\python.exe -m pytest
```

If the email file is not found, check the sample folder:

```cmd
dir examples
```

Disclaimer

MailGuard highlights indicators that may help with manual email investigation. It does not prove that an email is safe or malicious.