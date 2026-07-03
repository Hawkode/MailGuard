from __future__ import annotations

import json
from pathlib import Path

from mailguard.parser import EmailInvestigation
from mailguard.scoring import assess_email


def build_json_report(email: EmailInvestigation, source_file: str | Path | None = None) -> dict:
    assessment = assess_email(email)

    return {
        "source_file": str(source_file) if source_file else None,
        "risk": {
            "score": assessment.score,
            "verdict": assessment.verdict,
        },
        "headers": {
            "subject": email.subject,
            "from": email.from_address,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "date": email.date,
            "message_id": email.message_id,
        },
        "authentication_results": email.authentication_results,
        "received_headers": email.received_headers,
        "received_ips": [
           {
               "address": received_ip.address,
               "scope": received_ip.scope,
           }
           for received_ip in email.received_ips
        ],
        "findings": [
            {
                "points": finding.points,
                "message": finding.message,
            }
            for finding in assessment.findings
        ],
        "links": email.links,
        "attachments": [
            {
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "size_bytes": attachment.size_bytes,
                "sha256": attachment.sha256,
            }
            for attachment in email.attachments
        ],
        "summary": {
            "links_found": len(email.links),
            "attachments_found": len(email.attachments),
            "findings_found": len(assessment.findings),
        },
    }


def write_json_report(
    email: EmailInvestigation,
    output_path: str | Path,
    source_file: str | Path | None = None,
) -> Path:
    path = Path(output_path)

    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    report = build_json_report(email, source_file=source_file)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return path