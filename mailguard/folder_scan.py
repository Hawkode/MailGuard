from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


@dataclass
class FolderScanResult:
    scanned: int
    high_risk: int
    suspicious: int
    low_risk: int
    errors: int


def scan_folder(folder_path: str | Path) -> FolderScanResult:
    folder = Path(folder_path)

    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")

    if not folder.is_dir():
        raise NotADirectoryError(f"Path is not a folder: {folder}")

    scanned = 0
    high_risk = 0
    suspicious = 0
    low_risk = 0
    errors = 0

    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue

        try:
            email = parse_eml(file_path)
            assessment = assess_email(email)
            scanned += 1

            if assessment.verdict == "High risk":
                high_risk += 1
            elif assessment.verdict == "Suspicious":
                suspicious += 1
            else:
                low_risk += 1

        except Exception:
            errors += 1

    return FolderScanResult(
        scanned=scanned,
        high_risk=high_risk,
        suspicious=suspicious,
        low_risk=low_risk,
        errors=errors,
    )