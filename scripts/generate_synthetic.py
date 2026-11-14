"""Regenerate the synthetic data files in data/ (deterministic for a given seed).

    python scripts/generate_synthetic.py            (from the repository root)

Everything is fictional; see data/PROVENANCE.md. Private-key-looking blocks are NOT written to
disk, so the committed files cannot trip secret scanners.
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from veilchain.synth import generate_corpus, generate_records, person_name  # noqa: E402
from veilchain.tabular import write_csv  # noqa: E402

SEED = 1337


def main() -> None:
    data = ROOT / "data"
    records_path = data / "synthetic_records_500.csv"
    corpus_path = data / "synthetic_text_corpus.jsonl"
    for path in (records_path, corpus_path):
        if path.exists():
            print(f"{path.name} already exists; delete it first to regenerate.")
            return
    write_csv(records_path, ["record_id", "full_name", "email", "phone", "department", "data_sensitivity"], generate_records(500, SEED))
    known = [person_name(i) for i in range(10)]
    samples = generate_corpus(400, SEED, known, include_private_keys=False)
    with open(corpus_path, "x", encoding="utf-8", newline="\n") as handle:
        for sample in samples:
            handle.write(json.dumps({"id": sample.id, "kind": sample.kind, "text": sample.text,
                                     "spans": [asdict(s) for s in sample.spans]}, ensure_ascii=True) + "\n")
    print(f"Wrote {records_path.name} (500 records) and {corpus_path.name} ({len(samples)} labelled lines).")


if __name__ == "__main__":
    main()
