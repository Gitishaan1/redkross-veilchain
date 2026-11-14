# VeilChain detector evaluation

Corpus: 400 synthetic lines (seed 1337): 220 standard positives, 80 evasion attempts, 100 hard negatives. Ground truth comes from the generator.

| Group | Entity | Gold spans | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| evasion | EMAIL | 66 | 38 | 0 | 28 | 1.00 | 0.58 | 0.73 |
| evasion | PHONE | 14 | 14 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| standard | CARD | 19 | 19 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| standard | EMAIL | 96 | 96 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| standard | PERSON | 30 | 30 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| standard | PHONE | 64 | 64 | 8 | 0 | 0.89 | 1.00 | 0.94 |
| standard | RECORD_ID | 22 | 22 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| standard | SECRET | 50 | 50 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unknown name | PERSON | 29 | 0 | 0 | 29 | n/a | 0.00 | n/a |

How to read this: precision = how many flagged items were really sensitive; recall = how many sensitive items were found.
'unknown name' rows have recall near zero by design: a pattern detector cannot know a name it was never given.
False positives in the 'standard' group come from the hard negatives (for example a part number shaped like a phone number).
