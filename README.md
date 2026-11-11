# MailGuard

Phishing triage CLI for suspicious email files. MailGuard reads an `.eml` file and explains why it looks suspicious: Microsoft's own verdict, SPF/DKIM/DMARC alignment, links, attachments and sender identity, each with a score and a plain-English reason.

It never opens a link, runs or extracts an attachment, or sends email content anywhere. Everything happens on your machine.

**Status: complete (v0.2.0).** MailGuard is a lab and portfolio tool. It works alongside Microsoft Defender for Office 365, not instead of it: Defender gives the verdict, MailGuard shows the evidence behind it and the gaps it can miss.

## What it checks

| Area | Checks |
|---|---|
| **Microsoft verdict** | `CAT`, `SFV`, `SFTY`, `SCL` and connecting IP from `X-Forefront-Antispam-Report`, `BCL` from `X-Microsoft-Antispam`, and `compauth` with its reason code, each translated into plain English. Flags messages where an allow list or mail flow rule skipped filtering. |
| **Authentication** | SPF, DKIM and DMARC from the topmost `Authentication-Results` header, with relaxed alignment against the From domain. |
| **Sender identity** | Display names that claim a brand the sending domain does not own (Royal Mail, HMRC, Microsoft, DocuSign, UK banks and others). Addresses shown in the display name. Reply-To going to another organisation. |
| **Links** | Unwraps Microsoft Safe Links, Proofpoint URL Defense, Barracuda and Google redirects. Flags link text that shows one domain but goes to another, links written without `http(s)://` with "copy and paste this into your browser" wording, IP-address links, URL shorteners and plain HTTP. |
| **Attachments** | Grades executables, HTML/SVG pages, disk images, OneNote, macro documents and archives. Flags double extensions, right-to-left override file names, and files whose content does not match their name. Reads the ZIP file list, without extracting, to find risky inner files and password-protected archives. Flags emails that mention an attachment when none is attached. |
| **Content** | Whole-word keyword matches in the subject and visible text, capped so they support other evidence but never decide a verdict alone. |

## Install

Windows (Command Prompt):

```cmd
git clone https://github.com/Hawkode/MailGuard.git
cd MailGuard
py -m venv .venv
.venv\Scripts\activate
pip install -e ".[test]"
mailguard --help
```

Linux or macOS:

```bash
git clone https://github.com/Hawkode/MailGuard.git
cd MailGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
mailguard --help
```

Requires Python 3.10 or later.

## Usage

### 1. Get the email source

- **Outlook on the web or new Outlook:** open the message, select **...** > **View** > **View message source**, copy everything, and paste it into a text file named `message.eml`.
- **Microsoft Defender:** with Defender for Office 365 Plan 2, Threat Explorer lets admins with the right role download the original message.
- **Classic Outlook:** **File** > **Properties** > **Internet headers** gives the headers only. MailGuard still checks the Microsoft verdict, authentication and sender identity, but cannot check links or attachments.

Save real emails in the `samples\` folder. It is git-ignored, so they cannot be committed by accident.

### 2. Analyse it

```cmd
mailguard analyze samples\message.eml
```

Save a JSON report as well:

```cmd
mailguard analyze samples\message.eml --json reports\message.json
```

Scan a folder:

```cmd
mailguard scan-folder samples
```

## Example

A Royal Mail redelivery lure, delivered through Exchange Online with its link wrapped by Safe Links (`tests/fixtures/parcel_safelinks_lure.eml`):

```text
MailGuard Investigation Report

Risk score: 85/100
Verdict: High risk

Microsoft verdict (Exchange Online Protection)
Field      Value     Meaning
compauth   fail 001  No usable SPF, DKIM or DMARC, or only a weak policy

Subject: Your parcel is waiting - 1.45 GBP redelivery fee
From: Royal Mail <noreply@parcel-delivery-uk.example>

Findings:
- (+20) Microsoft composite authentication failed (reason 001): No usable SPF, DKIM or DMARC, or only a weak policy
- (+10) Envelope sender mailout.example.net differs from From parcel-delivery-uk.example, and authentication did not tie them together
- (+30) Display name claims Royal Mail, but the email comes from parcel-delivery-uk.example
- (+25) Link text shows www.royalmail.com but the link goes to parcel-redeliver.example.web.app

Links found: 1
1  https://parcel-redeliver.example.web.app/pay

Unwrapped links: 1
- Microsoft Safe Links > https://parcel-redeliver.example.web.app/pay
```

## Scoring

Each finding adds points, capped at 100:

| Score | Verdict | Meaning |
|---|---|---|
| 0 to 30 | Low risk | No strong indicators |
| 31 to 65 | Suspicious | Needs a person to look at it |
| 66 to 100 | High risk | Several strong indicators, or Microsoft already flagged it |

The score ranks emails by how much evidence they carry. It is not a calibrated probability.

## Safety design

- **No network access.** Links are decoded from their text, never visited. No lookups are made.
- **Attachments are never opened or extracted.** MailGuard hashes them, reads their first bytes, and reads the ZIP directory only.
- **Only the topmost Authentication-Results and Microsoft headers are trusted.** The receiving server adds those. Copies lower in the message can be planted by the sender.
- **Terminal output is sanitised.** Subjects, names, links and file names are attacker-controlled. Control characters and formatting codes are removed before printing, so a hostile subject line cannot hide or rewrite part of the report.
- **Real email stays local.** `samples/`, `datasets/`, `reports/` and `.env` are git-ignored. Test emails in `tests/fixtures/` are synthetic and use reserved `.example` domains.

## Limitations

- **No reputation lookups.** MailGuard does not query VirusTotal, URLhaus or similar services. Their free APIs restrict commercial and business use, so lookups are left to the analyst and the organisation's licensed tools.
- **A compromised real account that passes every check scores Suspicious at most.** The signals left are behavioural (plain-text links, "see attached" with no attachment), and a person has to confirm.
- **No QR code decoding** and **no Outlook `.msg` files.**
- **Mimecast links** use an encrypted token and cannot be decoded offline. They are recognised but not judged.
- **Top-level domains and brand domains are curated lists**, not a full public suffix list. A genuine brand email from a domain not on the list is flagged, and the finding says how to add it.
- **mbox files:** only the first message is read.

## Testing

```cmd
pytest -v
```

The suite includes a regression table (`tests/test_regression.py`) with the expected verdict for every fixture, so a scoring change that moves one fails the build. GitHub Actions runs the tests and a CLI smoke check on Python 3.10, 3.12 and 3.13 for every push and pull request.

## Project structure

```text
MailGuard/
├── .github/workflows/tests.yml   CI: tests and CLI smoke run
├── examples/suspicious.eml       Synthetic sample for the README
├── mailguard/
│   ├── cli.py            Command-line interface (analyze, scan-folder)
│   ├── parser.py         Reads the .eml: headers, bodies, links, attachments
│   ├── msverdict.py      Microsoft verdict headers
│   ├── auth.py           SPF, DKIM, DMARC and alignment
│   ├── brands.py         Brand impersonation in display names
│   ├── links.py          Links written without http(s)://
│   ├── unwrap.py         Safe Links, Proofpoint, Barracuda, Google redirects
│   ├── attachments.py    Attachment type, disguise and content checks
│   ├── headers.py        Received header IPs
│   ├── scoring.py        Findings and risk score
│   ├── report.py         Terminal report
│   ├── json_report.py    JSON report
│   └── folder_scan.py    Folder scan
├── tests/
│   ├── fixtures/         Synthetic test emails
│   └── test_*.py
├── CHANGELOG.md
└── pyproject.toml
```

## Disclaimer

MailGuard highlights indicators to support manual investigation. It does not prove that an email is safe or malicious.
