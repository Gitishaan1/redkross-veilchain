# Evidence

Everything here was produced by actually running VeilChain on synthetic data. Nothing was edited by hand. Console outputs are the raw transcripts.

| Path | What it is | Command that produced it |
|---|---|---|
| `demo_console_output.txt`, `demo_run/` | The full story: redact, verify, tamper, detect, restore, secrets | `veilchain demo --out evidence/demo_run` |
| `demo_run/01_customers/` | Evidence bundle for the 6 provided records (redacted CSV, ledger, manifest, summary, explanation) | part of the demo |
| `demo_run/02_testcases/` | Bundle for the four provided test cases RED-01 to RED-04 | part of the demo |
| `demo_run/03_*` | Tampered and restored copies, used to show detection and recovery | part of the demo |
| `demo_run/04_secrets/` | Result of redacting fake secrets: nothing derived from them is stored | part of the demo |
| `redteam_after_fixes/`, `redteam_console_output.txt` | Red-team report after the fixes | `veilchain redteam --out evidence/redteam_after_fixes` |
| `redteam_before_fixes/` | The red-team report from **before** two fixes (RT-5 BROKEN, RT-6 gaps). Its attack "a" also reflects a harness bug that was fixed afterwards (see `docs/BUILD_LOG.md`) | earlier run of the same command |
| `detector_evaluation.md` | Precision and recall on 400 labelled synthetic lines | `veilchain eval --size 400 --seed 1337 --out ...` |
| `synthetic_500_run/`, `synthetic_500_console_output.txt` | 500 records redacted with a k-anonymity threshold, then verified with a leak scan over 1,500 original values | `veilchain redact data/synthetic_records_500.csv ...` then `veilchain verify ... --leak-scan` |
| `pytest_output.txt` | Verbose log of all 85 tests (all pass) | `pytest -v --write-matrix docs/test_matrix.md` |
| `provided_files_sha256.txt` | SHA-256 of the three files supplied by RedKross, proving they are unmodified | `sha256sum` |

The demo uses the **public demo key** so the evidence is reproducible. Timestamps and run IDs in ledgers and manifests differ on each run; the redacted outputs do not.
