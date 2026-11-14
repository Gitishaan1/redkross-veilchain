# Learning journal: VeilChain (RedKross Task 2)

> This journal is built from what actually happened in the project (`docs/BUILD_LOG.md`, `docs/test_matrix.md`, `evidence/`). Sections marked **[Your reflection]** are for the intern to write in their own words after studying the code; they are intentionally left as prompts so that the journal never claims experiences that did not happen.

## 1. Concepts explained

### 1.1 Hash versus keyed hash (HMAC)
A hash such as SHA-256 turns any input into a fixed-length fingerprint. The same input always gives the same fingerprint, and a tiny change gives a completely different one. It proves two values are *equal*, not that either is trustworthy.
**In the project:** the first version of the pseudonym tokens was `SHA-256(value)`. Phone numbers have very few possibilities, so an attacker simply hashes every candidate number and compares. Red-team attack RT-1 recovered all 50 phone numbers in 0.6 seconds with no secret. The fix uses **HMAC**, a hash that also needs a secret key; the same attack recovered 0 of 50. The remaining weakness is key custody: with the key stolen, all 50 are recovered again.

### 1.2 Masking, pseudonymisation and anonymisation
*Masking* hides a value (`[EMAIL]`). *Pseudonymisation* replaces it with a consistent stand-in (`EMAIL#bf0641d28d`), so records can still be joined. *Anonymisation* means that nobody can be re-identified at all, which VeilChain does **not** claim: tokens stay stable, and combinations of harmless fields can still point at a person.
**In the project:** `--mode mask` versus the default tokens; RT-7 shows that the same key links releases (20/20) while different keys do not (0/20).

### 1.3 Classification as policy-as-code, and default deny
Instead of writing rules into the program, VeilChain reads the organisation's policy file, so the class order and the handling text come from the policy. A column the rules do not know about is treated as Confidential until someone classifies it ("default deny").
**In the project:** test TM-10 shows an unknown `notes` column being tokenised, and a secret pasted into an `email` column being removed instead of tokenised.

### 1.4 Hash chains and tamper evidence, and their limit
Each ledger entry stores the hash of the one before it, so changing, deleting or reordering any entry breaks every later hash. But a hash chain only proves *consistency*. An attacker who can rewrite the whole file and recompute every hash makes a perfectly consistent fake (RT-6h). A keyed seal (HMAC over the chain head) or an external copy of the head hash fixes that.
**In the project:** 7 of 8 tampering attacks are detected without the key and all 8 with it.

### 1.5 Quasi-identifiers and k-anonymity
Removing names is not enough if a combination of ordinary fields is unique. In the starter data, "People Ops + high" and "Engineering + medium" each describe exactly one record (k = 1), so someone who knows those two facts about a person can find their row. VeilChain reports this and can suppress those values. The cost is lost detail, and the word SUPPRESSED itself marks a record as unusual.

### 1.6 Fail closed, and why a leaked secret must be rotated
When VeilChain finds a password or key it removes it, stores nothing derived from it, and exits with code 2. The reason for the loud exit: removing a secret from one copy does not un-leak it. If it ever sat in a file that was shared or stored, it must be replaced.

### 1.7 Domain separation of keys
One master key produces three independent keys (token, audit, seal) with HMAC. Compromise or misuse of one purpose does not directly give the others, and a shared output file cannot be correlated with ledger fingerprints.

### 1.8 Precision and recall
Precision asks "of what I flagged, how much was really sensitive?"; recall asks "of what was sensitive, how much did I find?". In the evaluation, PHONE precision is 0.89 (a part number looks like a phone number) while recall is 1.00; unknown names have recall 0.00 because a pattern detector cannot know them.

## 2. One real mistake, how it was found, and what changed

**The mistake.** `.txt` input was redacted one line at a time. A private key spans several lines, so only the `-----BEGIN ... KEY-----` line was recognised and removed. The key *body*, on the following lines, was written to the output unchanged.

**How it was diagnosed.** Not by reading the code, but by **attacking the tool's own output**. Red-team attack RT-5 searches every output file for anything derived from the secrets (the raw value, base64, hex, SHA-256, and the HMAC tokens and fingerprints). It reported `BROKEN: 1 derivation found`. A short debugging script then printed which one: the key body line, raw, in the redacted file.

**What changed.** The `.txt` path now processes the whole file as a single text so a multi-line block is matched whole, and line numbers are still logged. A regression test (TM-11) uses a key block with two body lines and asserts the output is exactly `before`, `[RESTRICTED-REMOVED]`, `after`. RT-5 now reports DEFENDED.

**What it shows.** The unit tests passed before the red-team ran, because they tested single lines. Tests written by the same person who wrote the code share its blind spots. An attack written from the attacker's point of view found what the tests missed.

Other real findings (the manifest-forgery gap and a false positive on order numbers) are in `docs/BUILD_LOG.md`.

## 3. [Your reflection]

Write 5 to 10 sentences in your own words after you have run the demo and read the code:

- Which of the concepts above was new to you, and how would you explain it to a classmate?
- What surprised you when you ran `veilchain redteam`?
- Which limitation of VeilChain would you fix first, and why?
- What would you do differently if you built a second version?
