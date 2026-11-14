# VeilChain red-team report

All attacks use synthetic data generated at run time. DEFENDED = attack failed; PARTIAL = works only under a stated condition or is a documented limit; BROKEN = attack worked.

| ID | Attack | Outcome | Result |
|---|---|---|---|
| RT-1 | Brute-force reversal of pseudonym tokens | DEFENDED | v0 unkeyed tokens: BROKEN (50/50 recovered). v1 HMAC tokens: DEFENDED. With a stolen key: 50/50 recovered. |
| RT-2 | Leakage scan for originals and their encodings | DEFENDED | 0 leaks in 6 files; scanner self-test passed. |
| RT-3 | Linkage through quasi-identifiers (k-anonymity) | DEFENDED | k 1 -> 2; at-risk records 2 -> 0. |
| RT-4 | Obfuscated PII battery | PARTIAL | 12/12 designed-for evasions caught; 7 out-of-scope evasions slip through: letters spaced out, words: dot / at, reversed text, base64-encoded email, phone, digits only, no plus, phone spelled in words, card split across words. |
| RT-5 | Secrets: is anything derived from a Restricted value stored? | BROKEN | exit code 2; 1 derivations found in outputs. |
| RT-6 | Ledger and evidence tampering battery | BROKEN | 5/8 tampering attacks detected without the key; 6/8 with the key. Undetected without key: a, g, h. |
| RT-7 | Linkage across releases | DEFENDED | same key: 20/20 linkable; different keys: 0/20 linkable. |

## RT-1: Brute-force reversal of pseudonym tokens

Attacker goal: Recover real phone numbers from the redacted file.

- Search space: 1,000,000 candidate numbers; 50 distinct phone tokens in each output.
- v0 (unkeyed SHA-256 tokens): recovered 50/50 in 0.6s with no secret at all.
- v1 (keyed HMAC tokens), attacker without the key: recovered 0/50 in 0.5s.
- v1 with the token key stolen: recovered 50/50 in 1.6s. Key custody is the remaining weakness.
- Lesson: hashing a low-entropy value (a phone number) is not protection; a secret key is what makes it infeasible.

## RT-2: Leakage scan for originals and their encodings

Attacker goal: Find any original value anywhere in the evidence bundle.

- 150 original sensitive values searched for (and 7 kinds of re-encoding each) across 6 output files, including ledger and manifest.
- Leaks found in the real output: 0.
- Scanner self-test (a base64-encoded original planted in a copy): caught.

## RT-3: Linkage through quasi-identifiers (k-anonymity)

Attacker goal: Single out one person using department + label.

- Quasi-identifiers: department, data_sensitivity.
- Before suppression: k=1; records that a person who knows these facts could single out: REC-003, REC-004.
- After suppression (k-min 2): k=2; records still unique: none.
- Cost: the suppressed records lose their department and label, so analysis on those fields is no longer possible for them.
- Residual risk: the SUPPRESSED value itself marks a record as unusual. This is a simple check, not formal de-identification.

## RT-4: Obfuscated PII battery

Attacker goal: Hide an email, phone or card number from the detectors.

```
plain email                  caught
UPPER-CASE email             caught
plus-address email           caught
[at]/[dot] email             caught
(at)/(dot) with spaces       caught
spaced dots and @            caught
zero-width characters        caught
letters spaced out           MISSED
words: dot / at              MISSED
reversed text                MISSED
base64-encoded email         MISSED
phone with hyphens           caught
phone with dots              caught
phone with no separators     caught
full-width digits phone      caught
phone, digits only, no plus  MISSED
phone spelled in words       MISSED
card with spaces             caught
card split across words      MISSED
```

19 evasion attempts; the detectors are designed to handle 12 of them.
The cases marked MISSED that are not in the 'designed to handle' set are documented limits, not bugs: pattern matching cannot understand spelled-out, reversed or encoded data. A real deployment needs additional controls (DLP, review) for those.

## RT-5: Secrets: is anything derived from a Restricted value stored?

Attacker goal: Recover or confirm a secret from the ledger, manifest or output.

- Run exit code: 2 (2 = Restricted material found); manifest status: COMPLETE_RESTRICTED_FOUND.
- Searched every output file for 44 derivations of the secrets (raw, case, base64, hex, plain SHA-256 and prefixes, HMAC tokens and fingerprints).
- Derivations found anywhere: 1.
- Design: Restricted values are removed and nothing derived from them (no token, no fingerprint) is logged.
- Operational note: redaction does not un-leak a secret. Any secret found in data must be rotated.

## RT-6: Ledger and evidence tampering battery

Attacker goal: Alter evidence without verification noticing.

| Attack | detected without the key | detected with the key | what caught it |
|---|---|---|---|
| a. edit one ledger entry in place | NO | NO | hash chain |
| b. delete one ledger entry | yes | yes | chain and sequence numbers |
| c. swap two ledger entries | yes | yes | chain and sequence numbers |
| d. cut the end off the ledger | yes | yes | missing seal, manifest count |
| e. delete the ledger | yes | yes | missing file |
| f. alter the redacted output only | yes | yes | file hash |
| g. alter the output AND update the manifest | NO | NO | ledger run_end hash cross-check |
| h. rewrite output, ledger chain AND manifest | NO | yes | only the seal MAC (needs the key) |

Honest limit: a hash chain proves consistency, not authenticity. An attacker who can rewrite the ledger, recompute every hash and fix the manifest produces a bundle that verifies WITHOUT the key. The keyed seal (HMAC) closes that gap for anyone who holds the key, and publishing the ledger head hash somewhere the attacker cannot reach (for example a git commit) closes it for everyone.

## RT-7: Linkage across releases

Attacker goal: Join two separately shared files to follow a person over time.

- Two releases with the SAME key share 20/20 email tokens (records can be joined across releases).
- Two releases with DIFFERENT keys share 0/20 email tokens (releases cannot be joined).
- Design choice: use one key when joinability across files is required; use a fresh key per release when unlinkability matters more.
