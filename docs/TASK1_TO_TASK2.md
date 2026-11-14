# From Task 1 (rules) to Task 2 (enforcement)

Task 1 produced a data classification and handling guide for a fictional bank. VeilChain turns several of those written rules into running code. The Task 1 report also listed, as a limitation, that "a real bank may need finer sub-levels (for example, a restricted tier for cryptographic keys)". The Task 2 policy has exactly that tier (**Restricted**), and VeilChain implements it.

Task 1 repository: https://github.com/Gitishaan1/redkross-data-handling-guide

| Task 1 rule or finding | Where VeilChain enforces it |
|---|---|
| Classify by content, not container | `classify.py`: the field rule and the detected content are both considered and the higher class wins |
| Avoid over- and under-classification; do not trust labels blindly | label-versus-computed comparison: REC-001 and REC-005 are reported as under-classified |
| Unknown data is not "safe": default deny | unknown columns are Confidential until classified |
| Secrets must never be written into logs (Scenario 3, CWE-532) | Restricted values are removed and nothing derived from them is logged (RT-5, TM-08) |
| Logs are Confidential and tamper evidence matters; administrators should not be the only reviewers of their own logs | hash-chained ledger with a keyed seal; `verify` can be run by someone else |
| Disposal and deletion need evidence | the manifest and ledger record what was done, with hashes, without storing the data |
| Redact before sharing; least privilege | release level: only classes at or below it may stay in clear |
| Quasi-identifiers can re-identify (Task 1: "classification alone is not enough") | k-anonymity check and suppression |
| Report fast; the clock matters | exit code 2 and the ATTENTION banner: a Restricted find cannot pass silently |
| Be honest about limits | red-team report and BUILD_LOG list what does not work |
