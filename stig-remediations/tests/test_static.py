"""Source-alignment checks only; this does not parse or execute PowerShell.

Run with the public DISA archive explicitly supplied. No network, registry,
cloud access, installation, or generated test files are used.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
CATALOG = json.loads((ROOT / "catalog.json").read_text())
ARCHIVE = None


def source_rules():
    with zipfile.ZipFile(ARCHIVE) as archive:
        raw = archive.read(CATALOG["Benchmark"]["XmlMember"])
    document = ET.fromstring(raw)
    ns = {"x": document.tag.split("}")[0][1:]}
    rules = {}
    for group in document.findall("x:Group", ns):
        for rule in group.findall("x:Rule", ns):
            rules[rule.findtext("x:version", namespaces=ns)] = {
                "VulnerabilityId": group.get("id"),
                "RuleId": rule.get("id"),
                "Severity": rule.get("severity"),
                "Title": rule.findtext("x:title", namespaces=ns),
                "check": rule.findtext("x:check/x:check-content", namespaces=ns),
                "fix": rule.findtext("x:fixtext", namespaces=ns),
            }
    return raw, document, ns, rules


class SourceAlignment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.document, cls.ns, cls.rules = source_rules()

    def test_pinned_cached_archive_hashes_and_revision(self):
        # These pins came from the research copy, not an independent signed digest.
        meta = CATALOG["Benchmark"]
        self.assertEqual(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(), meta["ArchiveSha256"])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), meta["XmlSha256"])
        self.assertEqual(self.document.get("id"), meta["Id"])
        self.assertEqual(self.document.findtext("x:version", namespaces=self.ns), "2")
        release = self.document.find("x:plain-text[@id='release-info']", self.ns).text
        self.assertEqual(release, "Release: 11 Benchmark Date: 30 Sep 2026")
        self.assertEqual(meta["SourceUrl"], "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip")

    def test_all_fourteen_control_mappings_against_disa(self):
        self.assertEqual(len(CATALOG["Controls"]), 14)
        self.assertEqual(len({c["ControlId"] for c in CATALOG["Controls"]}), 14)
        for control in CATALOG["Controls"]:
            with self.subTest(control=control["ControlId"]):
                source = self.rules[control["ControlId"]]
                for field in ("VulnerabilityId", "RuleId", "Severity", "Title"):
                    self.assertEqual(control[field], source[field])
                check = source["check"]
                self.assertIn("Registry Hive: HKEY_LOCAL_MACHINE", check)
                self.assertEqual(control["Hive"], "LocalMachine")
                paths = []
                for line in check.splitlines():
                    if line.startswith("Registry Path:"):
                        path = re.sub(r"\s+\(.*$", "", line.split(":", 1)[1].strip()).strip("\\")
                        paths.append(path)
                self.assertEqual(control["RegistryPaths"], paths)
                self.assertEqual(control["ValueName"], re.search(r"Value Name:\s*(\S+)", check).group(1))
                self.assertIn("Value Type: REG_DWORD", check)
                self.assertEqual(control["ValueKind"], "DWord")
                value = re.search(r"\nValue:\s*(0x[0-9a-fA-F]+|\d+)", check).group(1)
                self.assertEqual(control["ExpectedValue"], int(value, 16 if value.startswith("0x") else 10))
                if control["Implementation"] == "prepared":
                    self.assertEqual(control["PolicyGuidance"], source["fix"])

    def test_applicability_and_management_exceptions_remain_deferred(self):
        candidates = {c["ControlId"]: c for c in CATALOG["Controls"]}
        deferred = {c["ControlId"] for c in candidates.values() if c["Implementation"] == "deferred"}
        self.assertEqual(deferred, {"WN11-CC-000005", "WN11-CC-000035", "WN11-CC-000305", "WN11-CC-000330"})
        self.assertIn("does not have a camera", self.rules["WN11-CC-000005"]["check"])
        self.assertEqual(len(candidates["WN11-CC-000305"]["RegistryPaths"]), 2)
        self.assertIn("Intune", self.rules["WN11-CC-000305"]["fix"])
        self.assertIn("Group Policy", self.rules["WN11-CC-000063"]["Title"])

    def test_ten_single_value_implementations_and_independent_expected_cases(self):
        prepared = [c for c in CATALOG["Controls"] if c["Implementation"] == "prepared"]
        self.assertEqual(len(prepared), 10)
        for c in prepared:
            with self.subTest(control=c["ControlId"]):
                folder = ROOT / c["ControlId"]
                self.assertEqual({p.name for p in folder.iterdir()}, {"remediate.ps1", "verify.ps1", "control.Tests.ps1", "report.md"})
                self.assertEqual(len(c["RegistryPaths"]), 1)
                remediation = (folder / "remediate.ps1").read_text()
                verification = (folder / "verify.ps1").read_text()
                cases = (folder / "control.Tests.ps1").read_text()
                self.assertIn("Invoke-StigRemediation -ControlId '" + c["ControlId"] + "'", remediation)
                self.assertIn("Test-StigControl -ControlId '" + c["ControlId"] + "'", verification)
                for field, expected in (("ExpectedRegistryPath", c["RegistryPaths"][0]), ("ExpectedValueName", c["ValueName"]), ("ExpectedRuleId", c["RuleId"])):
                    self.assertEqual(re.search("-" + field + r" '([^']+)'", cases).group(1), expected)
                self.assertEqual(int(re.search(r"-ExpectedValue (\d+)", cases).group(1)), c["ExpectedValue"])
                self.assertNotRegex(verification, r"\b(?:Invoke-StigRemediation|Set-ItemProperty|New-Item|Remove-Item|SetValue|CreateSubKey)\b")


class RepositoryChecks(unittest.TestCase):
    def test_no_deferred_implementation_directories(self):
        for c in CATALOG["Controls"]:
            if c["Implementation"] == "deferred":
                self.assertFalse((ROOT / c["ControlId"]).exists())

    def test_documentation_links_resolve_inside_checkout(self):
        docs = list(ROOT.rglob("*.md")) + list((REPO / "docs").glob("*.md")) + [REPO / "README.md"]
        for doc in docs:
            for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", doc.read_text()):
                if re.match(r"https?://", link):
                    continue
                path, _, anchor = link.partition("#")
                dest = (doc.parent / path).resolve()
                with self.subTest(file=str(doc.relative_to(REPO)), link=link):
                    self.assertTrue(dest.is_relative_to(REPO))
                    self.assertNotIn("Planning", dest.relative_to(REPO).parts)
                    self.assertTrue(dest.is_file())
                    if anchor:
                        headings = re.findall(r"^#+ (.+)$", dest.read_text(), re.M)
                        slugs = [re.sub(r"[^\w\s-]", "", h.lower()).replace(" ", "-") for h in headings]
                        self.assertIn(anchor, slugs)

    def test_new_artifacts_are_not_ignored(self):
        paths = [str(p.relative_to(REPO)) for p in ROOT.rglob("*") if p.is_file()]
        check = subprocess.run(["git", "--no-optional-locks", "check-ignore", "--no-index", "-z", "--stdin"], cwd=REPO, input=("\0".join(paths) + "\0").encode(), capture_output=True)
        self.assertEqual(check.returncode, 1, check.stdout.decode())

    def test_public_documents_exclude_administrative_framing(self):
        docs = list(ROOT.rglob("*.md")) + list((REPO / "docs").glob("*.md")) + [REPO / "README.md"]
        for doc in docs:
            with self.subTest(file=str(doc.relative_to(REPO))):
                self.assertNotRegex(doc.read_text().lower(), r"internship|\bhr\b|accepted credit|instructor answers:")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-archive", required=True, type=Path)
    options = parser.parse_args()
    ARCHIVE = options.benchmark_archive.resolve()
    if not ARCHIVE.is_file():
        parser.error("The explicitly supplied DISA archive does not exist.")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
