"""Read-only review aid for Git-visible source, links, and disclosure hazards.

Does not scan ignored directories or authenticate results. Findings name rules
and line numbers, never matched secret values. Human disclosure review remains required.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
PROTECTED_PARTS = {"planning", ".azure", ".aws", ".ssh", ".agents", ".codex", "private-evidence", "raw-evidence", "raw-telemetry", "credentials", "node_modules", ".git"}
PROTECTED_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".pcap", ".pcapng", ".evtx", ".dmp", ".nessus", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".pdf", ".zip", ".png", ".jpg", ".jpeg"}
REVIEWED_IMAGE_PATHS = frozenset({
    "stig-remediations/evidence/control-results.png",
    "vulnerability-management/evidence/assessment-overview.png",
    "cyber-defense/workbooks/evidence/workbook-overview.png",
    "threat-hunting/evidence/hunt-completion.png",
    "threat-hunting/evidence/hartwell-source-coverage.png",
    "threat-hunting/evidence/hartwell-analysis-checks.png",
    "docs/evidence/endpoint-response.png",
})
MAX_IMAGE_BYTES = 256 * 1024
MAX_TOTAL_IMAGE_BYTES = 1024 * 1024
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-credential": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"),
    "aws-access-key": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "azure-resource-id": re.compile(r"/subscriptions/[0-9a-fA-F-]{36}/"),
    "assigned-resource-name": re.compile(r"student-rg-[a-f0-9]{32,}|Cyber-Range-[0-9]+-(?:Admin|VNet|Subnet)"),
    "private-ip": re.compile(r"(?<![\d.])(?:10\.[0-9]{1,3}|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}(?![\d.])"),
    "literal-credential": re.compile(r'''(?i)(?:password|client_secret|access_token)\s*[=:]\s*["'][A-Za-z0-9+/=_-]{8,}["']'''),
    "literal-api-key": re.compile(r'''(?i)(?:["']?(?:access_key|secret_key|api_key|accessKey|secretKey)["']?\s*[=:]\s*["'][A-Za-z0-9_-]{32,}["']|(?:accessKey|secretKey)\s*=\s*[A-Za-z0-9_-]{32,}(?=\s|;|$))'''),
}


def protected(path):
    if path.as_posix() in REVIEWED_IMAGE_PATHS:
        return False  # Exact bytes are checked separately, not a directory exception.
    parts = {p.lower() for p in path.parts}
    name = path.name.lower()
    return bool(parts & PROTECTED_PARTS) or path.suffix.lower() in PROTECTED_SUFFIXES or name == ".env" or name.startswith(".env.") or name.endswith((".tfstate", ".tfstate.backup", ".parameters.local.json", ".private.json"))


def inspect_text(text):
    return [(number, name) for number, line in enumerate(text.splitlines(), 1) for name, pattern in PATTERNS.items() if pattern.search(line)]


def check_links(path, text, root):
    issues = []
    links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
    links += re.findall(r'''\b(?:href|src)=["']([^"']+)["']''', text, re.I)
    for link in links:
        if re.match(r"https?://", link):
            continue
        target, _, anchor = link.partition("#")
        dest = (path.parent / target).resolve() if target else path
        if not dest.is_relative_to(root) or protected(dest.relative_to(root)):
            issues.append("unsafe documentation link")
            continue
        if not dest.is_file():
            issues.append("broken documentation link")
        elif anchor:
            if dest.suffix != ".md":
                issues.append("documentation anchor on non-Markdown artifact")
                continue
            headings = re.findall(r"^#+ (.+)$", dest.read_text(), re.M)
            slugs = [re.sub(r"[^\w\s-]", "", h.lower()).replace(" ", "-") for h in headings]
            if anchor not in slugs:
                issues.append("broken documentation anchor")
    return issues


def load_reviewed_images(text):
    """Only the fixed reviewed paths; manifest fields cannot expand readable scope."""
    data = json.loads(text)
    images = data.get("images", [])
    if data.get("schema") != 1 or len(images) != len(REVIEWED_IMAGE_PATHS):
        raise ValueError("invalid image manifest")
    records = {r["path"]: r for r in images}
    if set(records) != REVIEWED_IMAGE_PATHS or data.get("image_count") != len(records):
        raise ValueError("image manifest paths differ from reviewed allowlist")
    for record in records.values():
        if not re.fullmatch(r"[a-f0-9]{64}", record["sha256"]):
            raise ValueError("invalid image digest")
        for field, maximum in (("bytes", MAX_IMAGE_BYTES), ("width", 1600), ("height", 2000)):
            if type(record[field]) is not int or not 0 < record[field] <= maximum:
                raise ValueError("image exceeds reviewed bounds")
    total = sum(r["bytes"] for r in records.values())
    if total > MAX_TOTAL_IMAGE_BYTES or data.get("total_bytes") != total:
        raise ValueError("image total differs from bounded manifest")
    return records


def inspect_reviewed_png(data, record):
    """Identity/structure checks only. Pixel disclosure needs visual review."""
    if len(data) > MAX_IMAGE_BYTES or len(data) != record["bytes"]:
        return ["image byte size differs from reviewed bounds"]
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        return ["image bytes differ from reviewed digest"]
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ["invalid PNG signature"]
    cursor, chunks = 8, []
    while cursor < len(data):
        if cursor + 12 > len(data):
            return ["truncated PNG chunk"]
        size = struct.unpack_from(">I", data, cursor)[0]
        kind = data[cursor + 4:cursor + 8]
        end = cursor + 12 + size
        if end > len(data) or kind not in (b"IHDR", b"IDAT", b"IEND"):
            return ["PNG metadata, unsupported or truncated chunk"]
        payload = data[cursor + 8:end - 4]
        if zlib.crc32(kind + payload) != struct.unpack_from(">I", data, end - 4)[0]:
            return ["PNG chunk checksum mismatch"]
        if kind == b"IHDR":
            if chunks or size != 13:
                return ["invalid PNG header"]
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            if (width, height) != (record["width"], record["height"]) or not (0 < width <= 1600 and 0 < height <= 2000):
                return ["PNG dimensions differ from reviewed bounds"]
            if (depth, compression, filtering, interlace) != (8, 0, 0, 0) or color not in (2, 6):
                return ["unsupported PNG encoding"]
        elif kind == b"IEND" and (size or end != len(data)):
            return ["PNG trailing data or invalid end"]
        chunks.append(kind)
        cursor = end
    if len(chunks) < 3 or chunks[0] != b"IHDR" or chunks[-1] != b"IEND" or any(c != b"IDAT" for c in chunks[1:-1]):
        return ["invalid PNG chunk sequence"]
    return []


def git(*args, data=None):
    return subprocess.run(["git", "--no-optional-locks", *args], cwd=ROOT, input=data, capture_output=True, check=False)


def main():
    listing = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if listing.returncode:
        print("Unable to enumerate Git-visible candidates.", file=sys.stderr)
        return 2
    paths = sorted(set(p for p in listing.stdout.decode().split("\0") if p))
    issues, inspected, image_count = [], 0, 0
    manifest = ROOT / "docs/visual-evidence.json"
    try:
        if manifest.is_symlink() or not manifest.resolve().is_relative_to(ROOT):
            raise ValueError("unsafe manifest path")
        reviewed_images = load_reviewed_images(manifest.read_text())
    except (OSError, ValueError, KeyError, TypeError):
        print("Unable to validate the exact reviewed-image manifest.", file=sys.stderr)
        return 2
    if not REVIEWED_IMAGE_PATHS.issubset(paths):
        issues.append(("docs/visual-evidence.json", "a reviewed image is missing from Git-visible candidates"))
    for name in paths:
        relative = Path(name)
        if protected(relative):
            issues.append(("[protected candidate]", "remove protected material from Git candidates; contents not read"))
            continue
        path = ROOT / relative
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            issues.append((name, "symlink or out-of-workspace candidate"))
            continue
        if not path.is_file():
            if name in REVIEWED_IMAGE_PATHS:
                issues.append((name, "reviewed image missing"))
            continue  # Working-tree deletion; never read its index contents.
        if name in REVIEWED_IMAGE_PATHS:
            if path.stat().st_size > MAX_IMAGE_BYTES:
                issues.append((name, "reviewed image exceeds size limit"))
                continue
            issues.extend((name, issue) for issue in inspect_reviewed_png(path.read_bytes(), reviewed_images[name]))
            image_count += 1
            continue
        try:
            text = path.read_text()
        except (UnicodeError, OSError):
            issues.append((name, "unreadable or binary candidate requires disclosure review"))
            continue
        inspected += 1
        issues.extend((name, f"line {line}: {rule}") for line, rule in inspect_text(text))
        if path.suffix == ".md":
            issues.extend((name, problem) for problem in check_links(path, text, ROOT))
            if name not in ("AGENTS.md", "CLAUDE.md") and re.search(r"(?i)internship|\bHR\b|accepted credit", text):
                issues.append((name, "administrative framing in engineering documentation"))
        if path.suffix == ".kql":
            for expected in ("let Start = datetime(null);", "let End = datetime(null);", "let DeviceScope = dynamic([]);", "where Timestamp >= Start and Timestamp < End", "where DeviceId in (DeviceScope)"):
                if expected not in text:
                    issues.append((name, "missing empty default or explicit time/device scope"))
    # Hypothetical paths only: do not enumerate or read any protected directory.
    sensitive = ["Planning/hypothetical.md", ".env", ".azure/msal_token_cache.json", "private-evidence/run.json", "capture.evtx", "export.nessus", "key.pfx", "state.tfstate", "notes.docx", "source.png"]
    ignored = git("check-ignore", "--no-index", "-z", "--stdin", data=("\0".join(sensitive) + "\0").encode())
    if ignored.returncode not in (0, 1) or set(filter(None, ignored.stdout.decode().split("\0"))) != set(sensitive):
        issues.append((".gitignore", "a representative protected path is not ignored"))
    for path, issue in issues:
        print(f"{path}: {issue}")
    print(f"Checked {inspected} Git-visible text files and {image_count} reviewed PNG images; {len(issues)} findings. No staging or writes performed.")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
