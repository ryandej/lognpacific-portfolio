"""Read-only review aid for Git-visible source, links, and disclosure hazards.

Does not scan ignored directories or authenticate results. Findings name rules
and line numbers, never matched secret values. Human disclosure review remains required.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROTECTED_PARTS = {"planning", ".azure", ".aws", ".ssh", ".agents", ".codex", "private-evidence", "raw-evidence", "raw-telemetry", "credentials", "node_modules", ".git"}
PROTECTED_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".pcap", ".pcapng", ".evtx", ".dmp", ".nessus", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".pdf", ".zip", ".png", ".jpg", ".jpeg"}
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
    parts = {p.lower() for p in path.parts}
    name = path.name.lower()
    return bool(parts & PROTECTED_PARTS) or path.suffix.lower() in PROTECTED_SUFFIXES or name == ".env" or name.startswith(".env.") or name.endswith((".tfstate", ".tfstate.backup", ".parameters.local.json", ".private.json"))


def inspect_text(text):
    return [(number, name) for number, line in enumerate(text.splitlines(), 1) for name, pattern in PATTERNS.items() if pattern.search(line)]


def check_links(path, text, root):
    issues = []
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
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
            headings = re.findall(r"^#+ (.+)$", dest.read_text(), re.M)
            slugs = [re.sub(r"[^\w\s-]", "", h.lower()).replace(" ", "-") for h in headings]
            if anchor not in slugs:
                issues.append("broken documentation anchor")
    return issues


def git(*args, data=None):
    return subprocess.run(["git", "--no-optional-locks", *args], cwd=ROOT, input=data, capture_output=True, check=False)


def main():
    listing = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if listing.returncode:
        print("Unable to enumerate Git-visible candidates.", file=sys.stderr)
        return 2
    paths = sorted(set(p for p in listing.stdout.decode().split("\0") if p))
    issues, inspected = [], 0
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
            continue  # Working-tree deletion; never read its index contents.
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
    print(f"Checked {inspected} Git-visible text files; {len(issues)} findings. No staging or writes performed.")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
