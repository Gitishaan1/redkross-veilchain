# Build log: real problems found while building VeilChain

This log lists problems that actually occurred during development, how each was found, and how it was fixed. It is kept because the way a security tool fails is more instructive than the way it works. Dates are from the build session (11-12 November 2026).

| # | What happened | How it was found | Fix | Proof it stays fixed |
|---|---|---|---|---|
| 1 | A 16-digit order number that fails the card checksum was partly flagged as a **phone number** (its first three groups of four digits looked like a grouped phone number). | Manual smoke test of hard negatives right after writing the detectors. | Grouped and parenthesised phone patterns are now rejected when they are joined by a space or hyphen to more digits (`_part_of_longer_digit_run`). | `test_hard_negatives_are_not_flagged`, `test_luhn_valid_card_detected_and_invalid_rejected` |
| 2 | A test asserted that `maya[at]example[dot]com` and `maya.example@example.com` normalise to the same value. They are **different addresses**. | The test failed on its first run. | The test was wrong, not the code. Corrected to `maya.example[at]example[dot]com`. | `test_same_real_value_gets_same_normalised_form` |
| 3 | The red-team harness crashed with `FileExistsError`: it tried to write the same synthetic input twice. | First run of `veilchain redteam`. | VeilChain's "never overwrite" safety (exclusive file creation) was working as designed; the harness was fixed to name files by size and seed and reuse them. | Red-team suite runs cleanly (TM-33 to TM-36). |
| 4 | **Security bug: a multi-line private key in a `.txt` file leaked its key body.** `.txt` input was redacted line by line, so only the `BEGIN` line was removed and the key lines after it stayed in the output. | Red-team attack **RT-5** (search every output for anything derived from a secret): outcome BROKEN, "1 derivation found". | `.txt` input is now processed as one text, so the whole block is matched; line numbers are still logged through `line_of`. | **TM-11** (regression test) and RT-5: BROKEN to DEFENDED. |
| 5 | **Evidence gap: an attacker could edit the redacted file *and* update the manifest to match**, and `verify` passed. | Red-team attack **RT-6g**. The first full run reported attacks "a, g, h" undetected without the key. | `verify` now cross-checks the input and output hashes recorded **inside the ledger** against the manifest ("ledger vs outputs"). | **TM-30** and RT-6: 5/8 to 7/8 detected without the key, 8/8 with it. |
| 6 | RT-6 attack "a" ("edit one ledger entry in place") reported *undetected*. | Same first run: suspicious, because a hash chain must catch that. | The attack picked a line that contained no `tokenise` text, so it changed nothing. The **harness** was wrong. It now edits a real decision. | RT-6 table in `evidence/redteam_after_fixes/`. |
| 7 | A secret pasted into an **email** or **unknown** column would have been tokenised (and fingerprinted) instead of removed, because those columns skipped content detection. | Design review of the Restricted rule ("nothing derived from a secret is kept"). | Every cell is scanned, even in columns declared as one entity; a Restricted hit removes the whole cell. | **TM-10** |

## Deliberate "failure" (not a bug)

The v0 pseudonym scheme (`--token-scheme unkeyed`, SHA-256 of the value) was kept on purpose as an insecure baseline. Red-team attack **RT-1** brute-forces it: all 50 phone numbers in the sample are recovered with no secret in about half a second (0.6 s). The keyed HMAC scheme (v1) resists the same attack. The before/after is recorded in **TM-33** and in `evidence/redteam_*`.

## Limits found and kept (not fixed, by design)

- A part number shaped like a phone number (`12-345-6789`) is flagged: 8 false positives in the 400-line evaluation (PHONE precision 0.89).
- Names that are not on the known-subjects list cannot be found by a pattern detector (recall 0.00 for unknown names).
- Evasions the detectors do not handle: letter-spaced, spelled-out, reversed and base64-encoded values (RT-4: 12 of 12 designed-for evasions caught, 7 out-of-scope ones slip through).
- A full, consistent rewrite of ledger, output and manifest by an attacker without the key is undetectable (RT-6h). The keyed seal or an external copy of the head hash closes that gap.

All numbers above come from the files in `evidence/`.
