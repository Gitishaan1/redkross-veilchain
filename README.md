# VeilChain

**A policy-driven data classifier and redactor with a tamper-evident audit ledger.**
RedKross Research Foundation internship: **Task 2** (Group F: Digital Forensics, Privacy and Cyber Resilience)
**Intern:** Ishaan Bansal | **Intern ID:** 2436

> **Demo video:** https://drive.google.com/file/d/1SLTWld8nY-Eobr6JEIpOGQ5vfeInLt7v/view?usp=sharing

> **Safety:** all data in this repository is **synthetic**. No real personal data, credentials or systems are involved, and nothing is tested against anything except VeilChain's own output. See [data/PROVENANCE.md](data/PROVENANCE.md).

---

## What it does

Given a CSV or text file and an organisation's classification policy, VeilChain:

1. **Classifies** every field and record (Public, Internal, Confidential, Restricted) and explains each decision by quoting the policy.
2. **Redacts** what must not be released: keyed pseudonym tokens (`EMAIL#bf0641d28d`), bare masks, or full removal for secrets and private keys.
3. **Logs every transformation without storing original values**, in a hash-chained ledger whose entries cannot be edited, deleted or reordered unnoticed.
4. **Seals an evidence bundle** (hashes of input, policy, outputs and ledger) that anyone can re-verify.
5. **Attacks its own output** (`veilchain redteam`) and reports honestly what holds and what does not.

```
input --> intake (SHA-256) --> classify --> decide --> transform --> redacted output
                                              |            |
                                              +--> ledger (hash chain, no originals) --> sealed manifest --> verify / redteam
```

Full diagram and module guide: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Ideas that make it different

| Idea | Where to see it |
|---|---|
| **Policy-as-code with explanations.** Class order and handling text come from the policy file; every decision quotes it (RED-03 is explained from the policy). | `veilchain redact ... --explain` |
| **Fail-closed secrets.** Restricted values are removed, nothing derived from them (no token, no fingerprint) is stored, and the run exits with code 2 and says "rotate this secret". | TM-07, TM-08, RT-5 |
| **Logs without originals.** Keyed fingerprints let an authorised reviewer confirm a value was processed; the ledger cannot be reversed. | `docs/ARCHITECTURE.md` |
| **Tamper-evident ledger + keyed seal**, with honest limits stated. | RT-6 |
| **A red team against itself:** brute-forces its own v0 tokens, hunts for leaks in 7 encodings, tests linkage, obfuscation and tampering. It found two real weaknesses, both fixed and regression-tested. | `docs/BUILD_LOG.md`, `evidence/redteam_*` |
| **Label audit.** The owner's low/medium/high label is compared with the computed class; under-classified records are reported. | `veilchain classify` |
| **Re-identification check** (k-anonymity) with optional suppression. | `veilchain risk`, `--k-min` |
| **Direct link to Task 1:** the Task 1 rules ("secrets never in logs", default deny, evidence for deletion) become running code. | [docs/TASK1_TO_TASK2.md](docs/TASK1_TO_TASK2.md) |

## Quick start

Requirements: **Python 3.10 or newer** (developed and tested on 3.12). No third-party packages are needed to run it; `pytest` is needed only for the tests.

```bash
git clone https://github.com/Gitishaan1/redkross-veilchain.git
cd redkross-veilchain
pip install -e .                 # installs the `veilchain` command (or use: python -m veilchain ...)
veilchain demo --out demo_out    # the whole story in one command
```

If you do not want to install it, run from the repository folder with the source on the path:

```powershell
# Windows PowerShell
$env:PYTHONPATH = "src"
python -m veilchain demo --out demo_out
```

```bash
# macOS / Linux
PYTHONPATH=src python3 -m veilchain demo --out demo_out
```

Output folders must be **new or empty** (VeilChain never overwrites evidence), so use a fresh `--out` name each time.

### The commands

| Command | What it does |
|---|---|
| `veilchain classify data/customer_records_synthetic.csv --k-min 2` | Shows how each column and record would be classified; flags label mismatches. Writes nothing. |
| `veilchain redact data/customer_records_synthetic.csv --out out1 --demo-key --k-min 2 --explain` | Redacts and writes the evidence bundle. |
| `veilchain redact data/redaction_test_cases.csv --out out2 --demo-key --text-column input_text --known-names-from data/customer_records_synthetic.csv --explain` | Redacts the four provided test cases (free text). |
| `veilchain verify out1 --demo-key --input data/customer_records_synthetic.csv --leak-scan` | Re-verifies hashes, ledger chain, seal and scans for leaks of the originals. |
| `veilchain risk data/customer_records_synthetic.csv --k-min 2` | k-anonymity report. |
| `veilchain redteam --out rt` | Attack suite (a few seconds). |
| `veilchain eval --size 400 --seed 1337` | Detector precision and recall on a labelled synthetic corpus. |
| `veilchain keygen ../my.key` | Creates a real key (refuses to write inside a git repository). |

**Keys.** `--demo-key` is public and only for demonstrations. For real runs use `--key-file` (create with `keygen`, keep it outside the repository) or set `VEILCHAIN_KEY`. With no key, a random one-run key is used: tokens are consistent within the run but cannot be reproduced later.

**Exit codes:** `0` success / verified; `1` verification failed; `2` run completed but Restricted material was found and removed; `3` usage or input error.

### Run the tests

```bash
pip install -r requirements-dev.txt
pytest                                   # 85 tests
pytest --write-matrix docs/test_matrix.md   # regenerates the test matrix from a real run
```

## Results at a glance

| Evidence | Result | Where |
|---|---|---|
| Automated tests | **85 passed**; 35 recorded as test-matrix cases with expected versus observed | [docs/test_matrix.md](docs/test_matrix.md), `evidence/pytest_output.txt` |
| Provided test cases RED-01 to RED-04 | all behave as specified (RED-03 kept and explained from the policy) | TM-02 |
| Red team | 5 of 7 attacks DEFENDED; 2 PARTIAL with stated conditions | [evidence/redteam_after_fixes/](evidence/redteam_after_fixes/redteam_report.md) |
| Real bugs found by attacking itself | multi-line private key leak; manifest forgery gap (both fixed) | [docs/BUILD_LOG.md](docs/BUILD_LOG.md) |
| Detector quality (400 synthetic lines) | standard PII precision and recall 1.00 except PHONE precision 0.89; unknown names recall 0.00 | [evidence/detector_evaluation.md](evidence/detector_evaluation.md) |
| Scale | 20,000 records in about 6 s | TM-18 |

## Repository map

```
README.md
src/veilchain/        the tool (standard library only)
policy/               provided Northstar policy (unmodified) + VeilChain rules
data/                 provided starter files (unmodified) + generated synthetic data + PROVENANCE.md
tests/                85 pytest tests (+ test-matrix plugin in conftest.py)
scripts/              generate_synthetic.py
evidence/             real run outputs, logs and the red-team reports (see evidence/README.md)
docs/                 Technical_Report (.md/.pdf), LEARNING_JOURNAL, ARCHITECTURE, BUILD_LOG,
                      TASK1_TO_TASK2, test_matrix, diagrams/
```

## Limitations (the short version)

- **Redaction is not anonymisation.** Tokens are stable per key; NIST SP 800-188 notes that masking alone is not de-identification.
- **Pattern detectors.** Unknown names and spelled-out, reversed or encoded values are missed.
- **Key custody.** A stolen token key reverses all tokens quickly.
- **A hash chain proves consistency, not authenticity.** A full consistent rewrite by an attacker without the key goes undetected unless the keyed seal or an external copy of the head hash is used.
- **Synthetic evaluation.** Precision and recall describe the generated corpus, not the real world.

Details and numbers: [docs/Technical_Report.pdf](docs/Technical_Report.pdf).

## Transparency

VeilChain was conceptualised, designed, developed, and tested by me as part of my internship project. My contributions include idea generation, system architecture, writing the source code, implementing all core functionalities, conducting test runs, debugging, security testing, and validating the results.

Claude (Anthropic) was used as a supplementary assistant for generating the MIT License, creating PDFs and diagrams, clarifying doubts about my proposed ideas, and explaining unfamiliar technical concepts during development.

All core implementation, technical decisions, and project testing were carried out by me.
Every number in the documentation comes from a command that was actually run; the logs are in `evidence/`.

## Documents

- [Technical report (PDF)](docs/Technical_Report.pdf) and [source](docs/Technical_Report.md)
- [Learning journal](docs/LEARNING_JOURNAL.md)
- [Architecture](docs/ARCHITECTURE.md), [Build log](docs/BUILD_LOG.md), [Test matrix](docs/test_matrix.md)
- Task 1 (the rules this implements): https://github.com/Gitishaan1/redkross-data-handling-guide

## License

MIT, see [LICENSE](LICENSE).
