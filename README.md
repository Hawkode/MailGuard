\# MailGuard



\## Overview



\*\*MailGuard\*\* is a defensive email investigation CLI designed to analyse suspicious `.eml` files.



It extracts useful email evidence such as sender headers, links, image URLs, and attachment details. The goal is to support manual phishing triage without opening links, downloading remote content, or executing attachments.



\## Features



\- \*\*Parse `.eml` files\*\*

\- \*\*Extract sender headers\*\*:

&#x20; - `From`

&#x20; - `Reply-To`

&#x20; - `Return-Path`

&#x20; - `Date`

&#x20; - `Message-ID`

\- \*\*Extract links\*\* from plain text and HTML email bodies

\- \*\*Detect image URLs\*\* inside HTML emails

\- \*\*List attachments\*\* with filename, content type, and size

\- \*\*Generate a readable terminal investigation report\*\*

\- \*\*Includes a synthetic sample email for testing\*\*

\- \*\*Includes basic parser tests with pytest\*\*



\## Current Status



Completed:



\- Basic email parser

\- CLI command

\- Link extraction

\- Attachment listing

\- Terminal report output

\- Synthetic test email

\- Basic pytest test



Planned:



\- Risk scoring

\- SPF, DKIM, and DMARC checks

\- Sender IP extraction from `Received` headers

\- Suspicious keyword detection

\- URL risk analysis

\- Attachment hashing

\- JSON report output

\- Markdown report output

\- GitHub Actions workflow



\## Installation



\### 1. Clone the Repository



```cmd

git clone https://github.com/Hawkode/MailGuard.git

cd MailGuard

```



\### 2. Create a Virtual Environment



```cmd

py -m venv .venv

```



\### 3. Activate the Virtual Environment



```cmd

.venv\\Scripts\\activate

```



\### 4. Install the Project



```cmd

pip install -e .

```



\### 5. Install Test Dependencies



```cmd

pip install pytest

```



\## Usage



Analyse the included sample email:



```cmd

mailguard analyze examples\\suspicious.eml

```



Alternative command:



```cmd

.venv\\Scripts\\python.exe -m mailguard.cli analyze examples\\suspicious.eml

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



\## Testing



Run the test suite:



```cmd

.venv\\Scripts\\python.exe -m pytest

```



Expected result:



```text

1 passed

```



\## Project Structure



```text

mailguard/

├── mailguard/

│   ├── \_\_init\_\_.py

│   ├── cli.py

│   ├── parser.py

│   └── report.py

├── tests/

│   └── test\_parser.py

├── examples/

│   └── suspicious.eml

├── README.md

├── pyproject.toml

└── .gitignore

```



\## Safety



MailGuard is built for defensive email analysis.



It does not:



\- open URLs

\- visit websites

\- download remote images

\- execute attachments

\- upload email content anywhere



Only synthetic sample emails should be committed to this repository.



Do not commit:



\- real emails

\- private reports

\- API keys

\- personal data

\- live investigation files



\## Troubleshooting



\### `mailguard` command is not found



Use the alternative command:



```cmd

.venv\\Scripts\\python.exe -m mailguard.cli analyze examples\\suspicious.eml

```



Or reinstall the project:



```cmd

pip install -e .

```



\### Tests do not run



Check that the virtual environment is active and pytest is installed:



```cmd

.venv\\Scripts\\python.exe -m pip install pytest

.venv\\Scripts\\python.exe -m pytest

```



\### Email file not found



Check that the `.eml` file path is correct:



```cmd

dir examples

```



\## Disclaimer



MailGuard highlights indicators that may help with manual email investigation. It does not prove that an email is safe or malicious.

