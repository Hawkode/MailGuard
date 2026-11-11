"""Judge attachments by type, disguise and real content, without opening them.

Nothing is executed or extracted. ZIP archives are inspected by reading
their file list only, using the standard library.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePath
import io
import re
import zipfile

EXECUTABLE = {
    ".exe", ".scr", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".wsh", ".hta", ".bat", ".cmd", ".ps1", ".msi", ".msix", ".appx",
    ".lnk", ".cpl", ".jar", ".reg", ".dll", ".xll", ".iqy", ".slk",
    ".url", ".chm", ".inf", ".scf", ".application", ".gadget",
}
# HTML and SVG files open in the browser and are used for fake login pages.
WEB_PAGE = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".svgz", ".mht", ".mhtml"}
DISK_IMAGE = {".iso", ".img", ".vhd", ".vhdx", ".one"}
MACRO_DOCUMENT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam"}
ARCHIVE = {".zip", ".rar", ".7z", ".cab", ".gz", ".tar", ".tgz", ".ace", ".arj", ".xz", ".z", ".uue", ".bz2"}
DOCUMENT_LOOKALIKE = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".jpg", ".jpeg", ".png", ".rtf"}

RIGHT_TO_LEFT_OVERRIDE = "‮"


@dataclass
class AttachmentRisk:
    points: int
    message: str


def risk_class(extension: str) -> tuple[int, str] | None:
    if extension in EXECUTABLE:
        return 40, "executable or script"
    if extension in WEB_PAGE:
        return 35, "web page that opens in the browser, a common fake login page"
    if extension in DISK_IMAGE:
        return 30, "disk image or OneNote file, used to bypass Mark of the Web"
    if extension in MACRO_DOCUMENT:
        return 30, "Office document with macros"
    if extension in ARCHIVE:
        return 15, "archive that can hide other files"
    return None


def sniff_content(payload: bytes) -> str:
    """Rough real file type from the first bytes."""
    head = payload[:512].lstrip().lower()
    if payload.startswith(b"MZ"):
        return "executable"
    if payload.startswith(b"%PDF"):
        return "pdf"
    if payload.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith((b"<!doctype html", b"<html", b"<script")) or b"<html" in head:
        return "html"
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    return ""


# ZIP-based Office formats legitimately start with PK.
ZIP_CONTAINERS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip", ".jar", ".odt", ".ods"}


def inspect_zip(payload: bytes) -> tuple[bool, list[str]]:
    """Return (encrypted, risky inner file names) from the ZIP directory."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return False, []

    encrypted = any(info.flag_bits & 0x1 for info in infos)
    risky = [
        info.filename
        for info in infos
        if PurePath(info.filename).suffix.lower() in EXECUTABLE | WEB_PAGE | DISK_IMAGE | MACRO_DOCUMENT
    ]
    return encrypted, risky


def assess_attachment(filename: str, payload: bytes, inline: bool = False) -> list[AttachmentRisk]:
    risks: list[AttachmentRisk] = []
    name = filename or "unknown"
    suffixes = [s.lower() for s in PurePath(name.replace(RIGHT_TO_LEFT_OVERRIDE, "")).suffixes]
    extension = suffixes[-1] if suffixes else ""

    if RIGHT_TO_LEFT_OVERRIDE in name:
        risks.append(AttachmentRisk(35, f"File name uses a hidden right-to-left character to fake its extension: {name!r}"))

    classified = risk_class(extension)
    if classified:
        points, label = classified
        # An SVG logo embedded in a signature is less telling than one sent as a file.
        if inline and extension in WEB_PAGE:
            points = 15
        risks.append(AttachmentRisk(points, f"Risky attachment, {label}: {name}"))

        if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT_LOOKALIKE:
            risks.append(AttachmentRisk(15, f"Double extension disguises it as {suffixes[-2]}: {name}"))

    real = sniff_content(payload)
    if extension in DOCUMENT_LOOKALIKE and real in {"executable", "html", "svg"}:
        risks.append(AttachmentRisk(35, f"Named {extension} but the content is {real}: {name}"))
    elif extension in DOCUMENT_LOOKALIKE and real == "zip" and extension not in ZIP_CONTAINERS:
        risks.append(AttachmentRisk(20, f"Named {extension} but the content is a ZIP archive: {name}"))

    if real == "zip" or extension == ".zip":
        encrypted, inner = inspect_zip(payload)
        if encrypted:
            risks.append(AttachmentRisk(25, f"Password-protected archive, so it cannot be scanned: {name}"))
        for inner_name in inner[:3]:
            risks.append(AttachmentRisk(30, f"Archive {name} contains a risky file: {inner_name}"))

    return risks


ATTACHMENT_MENTION = re.compile(
    r"\b(?:see|find|open|review|view)\s+(?:the\s+)?attached\b"
    r"|\battached\s+(?:is|are|document|file|invoice|statement|remittance|copy|pdf)\b"
    r"|\bplease\s+find\s+attached\b",
    re.IGNORECASE,
)


def mentions_missing_attachment(visible_text: str, has_real_attachment: bool) -> bool:
    """True when the text points to an attachment that is not there."""
    return not has_real_attachment and bool(ATTACHMENT_MENTION.search(visible_text or ""))
