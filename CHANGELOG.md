# Changelog

## 0.2.0 (2026-11-11)

Detection now covers the lures seen in real Exchange Online triage, and false positives on legitimate bulk mail are cut.

### Added
- Microsoft verdict: `CAT`, `SFV`, `SFTY`, `SCL`, `BCL` and `compauth` with reason codes, read from the topmost headers only.
- Links written without `http(s)://`, and "copy and paste this link" wording.
- Unwrapping of Safe Links, Proofpoint URL Defense, Barracuda and Google redirects.
- Link text that shows one domain but goes to another.
- Brand impersonation in display names, and addresses shown in display names.
- Attachment grading by type, double extensions, right-to-left override names, content that does not match the extension, ZIP inner files and password-protected archives.
- Emails that mention an attachment when none is attached.
- Regression test table, CLI tests and GitHub Actions on Python 3.10, 3.12 and 3.13.

### Changed
- SPF, DKIM and DMARC use relaxed alignment against the From domain; no double counting when `compauth` is present.
- A different Return-Path only counts when authentication does not tie the message to the From domain.
- Keywords match whole words in the subject and visible text, capped at three.
- Ordinary attachments (PDF, Office, images) no longer add points.
- Documentation IP ranges are labelled `documentation`, not `private`.

### Security
- Terminal output strips control characters and escapes formatting in attacker-controlled text.

### Removed
- Committed `__pycache__` files.

## 0.1.0

First release: header, link and attachment extraction, SPF/DKIM/DMARC checks, keyword scoring, JSON report and folder scan.
