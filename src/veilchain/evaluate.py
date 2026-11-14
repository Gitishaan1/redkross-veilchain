"""Measure detector quality on a labelled synthetic corpus.

A detection counts as a true positive if it overlaps a ground-truth span of the same entity.
Predictions that overlap no ground-truth span of that entity are false positives. Ground-truth
spans with no overlapping prediction are false negatives.

Results are reported in groups, because one blended number would hide the interesting facts:
  * standard      ordinary PII that the detectors are designed for;
  * evasion       obfuscated PII (zero-width characters, full-width digits, "[at]", ...);
  * unknown name  names that are not on the known-subjects list (cannot be detected by design).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .detectors import DetectorSet
from .errors import OutputError
from .policy import Policy
from .rules import load_rules
from .synth import FIRST, LAST, Sample, Span, generate_corpus, person_name


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def evaluate(samples: list[Sample], detectors: DetectorSet) -> dict:
    """Return metrics grouped by (group, entity)."""
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"gold": 0, "tp": 0, "fp": 0, "fn": 0})
    for sample in samples:
        predicted = detectors.detect(sample.text)
        matched_pred: set[int] = set()
        for span in sample.spans:
            group = "unknown name" if (span.entity == "PERSON" and not span.known) else ("evasion" if sample.kind == "evasion" else "standard")
            bucket = counts[(group, span.entity)]
            bucket["gold"] += 1
            hit = None
            for index, pred in enumerate(predicted):
                if pred.entity == span.entity and _overlaps(pred.start, pred.end, span.start, span.end):
                    hit = index
                    break
            if hit is None:
                bucket["fn"] += 1
            else:
                bucket["tp"] += 1
                matched_pred.add(hit)
        for index, pred in enumerate(predicted):
            if index in matched_pred:
                continue
            overlaps_gold = any(g.entity == pred.entity and _overlaps(pred.start, pred.end, g.start, g.end) for g in sample.spans)
            if not overlaps_gold:
                group = "evasion" if sample.kind == "evasion" else "standard"
                counts[(group, pred.entity)]["fp"] += 1
    rows = []
    for (group, entity), c in sorted(counts.items()):
        precision = c["tp"] / (c["tp"] + c["fp"]) if (c["tp"] + c["fp"]) else None
        recall = c["tp"] / c["gold"] if c["gold"] else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if precision is not None and recall is not None else None)
        rows.append({"group": group, "entity": entity, **c, "precision": precision, "recall": recall, "f1": f1})
    totals = {"samples": len(samples), "positives": sum(1 for s in samples if s.kind == "positive"),
              "evasions": sum(1 for s in samples if s.kind == "evasion"), "negatives": sum(1 for s in samples if s.kind == "negative")}
    return {"totals": totals, "rows": rows}


def _fmt(value) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_markdown(result: dict, seed: int) -> str:
    t = result["totals"]
    lines = [
        "# VeilChain detector evaluation",
        "",
        f"Corpus: {t['samples']} synthetic lines (seed {seed}): {t['positives']} standard positives, "
        f"{t['evasions']} evasion attempts, {t['negatives']} hard negatives. Ground truth comes from the generator.",
        "",
        "| Group | Entity | Gold spans | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in result["rows"]:
        lines.append(f"| {r['group']} | {r['entity']} | {r['gold']} | {r['tp']} | {r['fp']} | {r['fn']} | "
                     f"{_fmt(r['precision'])} | {_fmt(r['recall'])} | {_fmt(r['f1'])} |")
    lines += [
        "",
        "How to read this: precision = how many flagged items were really sensitive; recall = how many sensitive items were found.",
        "'unknown name' rows have recall near zero by design: a pattern detector cannot know a name it was never given.",
        "False positives in the 'standard' group come from the hard negatives (for example a part number shaped like a phone number).",
    ]
    return "\n".join(lines) + "\n"


def build_detectors(rules, known_names: list[str]) -> DetectorSet:
    return DetectorSet(rules.record_id_pattern, known_names)


def run_eval_command(args) -> int:
    policy = Policy.load(args.policy)
    rules = load_rules(args.rules, policy)
    known = [person_name(i) for i in range(10)]
    if args.corpus:
        samples = []
        for line in Path(args.corpus).read_text(encoding="utf-8").splitlines():
            obj = json.loads(line)
            samples.append(Sample(obj["id"], obj["kind"], obj["text"], [Span(**s) for s in obj["spans"]]))
    else:
        samples = generate_corpus(args.size, args.seed, known)
    result = evaluate(samples, build_detectors(rules, known))
    report = render_markdown(result, args.seed)
    print(report)
    if args.out:
        out = Path(args.out)
        if out.exists():
            raise OutputError(f"Refusing to overwrite {out}")
        out.write_text(report, encoding="utf-8", newline="\n")
        print(f"Report written to {out}")
    return 0
