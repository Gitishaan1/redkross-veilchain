"""Evidence bundle: a manifest that records what was produced, plus verification of it.

The manifest lists the SHA-256 of the input, the policy, the rules, every output file and the
ledger head. `verify_bundle` re-computes everything and reports each check as PASS / FAIL /
WARN / INFO.

This follows the spirit of the NIST SP 800-86 forensic process (collection, examination,
analysis, reporting): hash at intake, record every transformation, re-verify before relying on
the result. VeilChain is NOT a forensic acquisition tool, and a hash only proves that a file
matches a recorded value. It does not prove the original data was trustworthy.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import __version__
from .hashing import constant_time_equal, sha256_bytes, sha256_file
from .keys import KeyRing
from .leakscan import collect_canaries, scan_paths
from .ledger import read_entries, verify_ledger

MANIFEST_NAME = "manifest.json"
MANIFEST_HASH_NAME = "manifest.sha256"

NOTES = [
    "A SHA-256 hash proves that a file matches a recorded value. It does not prove the original data was trustworthy.",
    "This manifest contains no original sensitive values, no key material, no absolute paths and no usernames.",
    "Redaction reduces exposure; it does not make data anonymous. See the report's limitations.",
]


def describe_file(path: Path) -> dict:
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size}


def write_manifest(outdir: Path, manifest: dict) -> str:
    """Write manifest.json and manifest.sha256. Returns the manifest hash."""
    body = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    (outdir / MANIFEST_NAME).write_text(body, encoding="utf-8", newline="\n")
    digest = sha256_bytes(body.encode("utf-8"))
    (outdir / MANIFEST_HASH_NAME).write_text(f"{digest}  {MANIFEST_NAME}\n", encoding="utf-8", newline="\n")
    return digest


def new_manifest(**fields) -> dict:
    manifest = {"tool": "veilchain", "version": __version__, "manifest_version": 1, "python": platform.python_version()}
    manifest.update(fields)
    manifest["notes"] = NOTES
    return manifest


@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | WARN | INFO
    detail: str = ""


@dataclass
class BundleReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def ok(self) -> bool:
        return not any(c.status == "FAIL" for c in self.checks)

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=10)
        lines = []
        for c in self.checks:
            lines.append(f"  [{c.status:<4}] {c.name:<{width}}  {c.detail}".rstrip())
        lines.append("")
        lines.append("RESULT: " + ("VERIFIED - every check passed." if self.ok else "VERIFICATION FAILED - see the FAIL lines above."))
        return "\n".join(lines)


def verify_bundle(
    outdir: Path | str,
    keyring: Optional[KeyRing] = None,
    input_path: Optional[str | Path] = None,
    leak_scan: bool = False,
    policy=None,
    rules=None,
    detectors=None,
) -> BundleReport:
    outdir = Path(outdir)
    report = BundleReport()
    manifest_path = outdir / MANIFEST_NAME
    hash_path = outdir / MANIFEST_HASH_NAME

    if not manifest_path.is_file():
        report.add("manifest present", "FAIL", f"{MANIFEST_NAME} not found in {outdir.name}/")
        return report
    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        report.add("manifest readable", "FAIL", "manifest.json is not valid JSON")
        return report
    report.add("manifest present", "PASS", MANIFEST_NAME)

    # 1. The manifest itself.
    if hash_path.is_file():
        parts = hash_path.read_text(encoding="utf-8").split()
        recorded = parts[0] if parts else ""
        if constant_time_equal(recorded, sha256_bytes(manifest_bytes)):
            report.add("manifest hash", "PASS", "manifest.json matches manifest.sha256")
        else:
            report.add("manifest hash", "FAIL", "manifest.json does not match manifest.sha256 (manifest was edited)")
    else:
        report.add("manifest hash", "WARN", "manifest.sha256 is missing, so the manifest itself cannot be checked")

    # 2. Every listed file.
    listed = manifest.get("files", {})
    for name, meta in sorted(listed.items()):
        path = outdir / name
        if not path.is_file():
            report.add(f"file {name}", "FAIL", "MISSING")
            continue
        actual = sha256_file(path)
        if constant_time_equal(actual, str(meta.get("sha256", ""))):
            report.add(f"file {name}", "PASS", f"unchanged ({actual[:12]}...)")
        else:
            report.add(f"file {name}", "FAIL", f"CHANGED (expected {str(meta.get('sha256', ''))[:12]}..., found {actual[:12]}...)")
    for path in sorted(outdir.iterdir()):
        if path.is_file() and path.name not in listed and path.name not in (MANIFEST_NAME, MANIFEST_HASH_NAME):
            report.add(f"file {path.name}", "WARN", "present in the folder but not listed in the manifest")

    # 3. The ledger.
    ledger_meta = manifest.get("ledger", {})
    ledger_path = outdir / "ledger.jsonl"
    seal_key = None
    if keyring is not None:
        if keyring.source == "ephemeral":
            report.add("seal key", "INFO", "an ephemeral key cannot verify an earlier run")
        else:
            seal_key = keyring.seal_key
            recorded_id = manifest.get("key", {}).get("key_id")
            if recorded_id and recorded_id != keyring.key_id:
                report.add("key id", "WARN", "the supplied key's id differs from the manifest's key id (wrong key?)")
    lr = verify_ledger(ledger_path, seal_key)
    if lr.ok:
        report.add("ledger chain", "PASS", f"{lr.entries} entries, chain intact, sealed")
    else:
        report.add("ledger chain", "FAIL", "; ".join(lr.problems[:3]))
    if lr.mac_checked:
        report.add("ledger seal MAC", "PASS" if lr.mac_ok else "FAIL", "keyed seal verifies" if lr.mac_ok else "keyed seal does not verify")
    else:
        report.add("ledger seal MAC", "INFO", "not checked (no usable key supplied); chain is consistent but not authenticated")
    if lr.head is not None:
        if ledger_meta.get("entries") == lr.entries and ledger_meta.get("head") is not None:
            report.add("ledger vs manifest", "PASS", "entry count matches the manifest")
        else:
            report.add("ledger vs manifest", "FAIL", "entry count differs from the manifest")

    # 3b. Cross-check: the ledger independently records the input and output hashes. If someone edits
    # an output and then "fixes" the manifest to match, the ledger no longer agrees.
    if lr.entries:
        try:
            entries = read_entries(ledger_path)
            run_end = next((e for e in reversed(entries) if e.get("event") == "run_end"), None)
            run_start = next((e for e in entries if e.get("event") == "run_start"), None)
            problems = []
            if run_end:
                out = run_end["data"].get("output", {})
                listed_hash = listed.get(out.get("name"), {}).get("sha256")
                if out.get("sha256") != listed_hash:
                    problems.append("output hash recorded in the ledger differs from the manifest")
            if run_start:
                wanted = run_start["data"].get("input", {}).get("sha256")
                if wanted not in {i.get("sha256") for i in manifest.get("inputs", [])}:
                    problems.append("input hash recorded in the ledger differs from the manifest")
            if problems:
                report.add("ledger vs outputs", "FAIL", "; ".join(problems))
            else:
                report.add("ledger vs outputs", "PASS", "input and output hashes inside the ledger agree with the manifest")
        except (OSError, ValueError, KeyError):
            report.add("ledger vs outputs", "FAIL", "could not read the hashes recorded in the ledger")

    # 4. Key and status information.
    key_info = manifest.get("key", {})
    if key_info.get("source") == "demo":
        report.add("key source", "WARN", "DEMO key: it is public, so these tokens give no real protection")
    elif key_info.get("source") == "ephemeral":
        report.add("key source", "INFO", "ephemeral key: tokens cannot be reproduced and the seal cannot be authenticated later")
    if manifest.get("status") == "COMPLETE_RESTRICTED_FOUND":
        report.add("restricted material", "WARN", "Restricted material was found and removed. Treat the original secret as exposed and rotate it.")

    # 5. The original input.
    if input_path is not None:
        ip = Path(input_path)
        if not ip.is_file():
            report.add("input file", "FAIL", "MISSING")
        else:
            wanted = {i.get("sha256") for i in manifest.get("inputs", [])}
            actual = sha256_file(ip)
            if actual in wanted:
                report.add("input file", "PASS", "matches the hash recorded at intake (original untouched)")
            else:
                report.add("input file", "FAIL", "does not match the hash recorded at intake (input CHANGED or is a different file)")
        if leak_scan and ip.is_file() and policy is not None:
            params = manifest.get("parameters", {})
            canaries = collect_canaries(
                ip, policy, rules, detectors,
                frozenset(c.lower() for c in params.get("text_columns", [])),
                params.get("release_level", "Internal"),
            )
            paths = [p for p in outdir.iterdir() if p.is_file()]
            findings, scanned = scan_paths(paths, canaries)
            if findings:
                summary = ", ".join(sorted({f"{f.file}:{f.variant}" for f in findings})[:4])
                report.add("leak scan", "FAIL", f"{len(findings)} leak(s) of {scanned} original values found ({summary})")
            else:
                report.add("leak scan", "PASS", f"none of {scanned} original sensitive values (nor their encodings) appear in any output file")
    return report
