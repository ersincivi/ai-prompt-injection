#!/usr/bin/env python3
"""
render_inventory_md.py — render the IPI-v2 catalog as a single
human-readable Markdown inventory.

Source of truth: `cargo run --release --bin dump_ipi_catalog` (the
same canonical 100-vector JSON the test-matrix harness consumes).
The Markdown never lives in vectors.rs — running this script regenerates it
when the catalog drifts.

Usage:
    python3 scripts/ipi/render_inventory_md.py \
        > docs/vector-inventory.md
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORE_DIR = REPO_ROOT / "core"

# Display labels per VectorCategory enum (matches /core::ipi::vectors comments)
CATEGORY_LABEL = {
    "PrivacyTargeted":        ("A", "Privacy-targeted",        "BRAND ANGLE — user PII exfiltration prompts"),
    "Multimodal":             ("B", "Multimodal cross-channel","Text defences bypassed via image/audio/PDF/QR/EXIF/LSB/Unicode-tag"),
    "ToolChainConfusion":     ("C", "Tool-chain confusion",    "Fake MCP / fn-call fragment / JSON-LD intent / confused-deputy"),
    "AuthorityImpersonation": ("D", "Authority impersonation", "Fake Constitutional AI · HTML <!--SYSTEM--> · brand/cert · subpoena"),
    "MetaLevel":              ("E", "Meta-level",              "Training-data contamination self-test · CoT leak · vendor fingerprint"),
    "MemoryExploitation":     ("F", "Memory & context exploit","Context-window position · calibration drift · summarisation handoff"),
    "IndirectChain":          ("G", "Indirect chain",          "False prior-conversation / pre-analysed claim / implicit user consent"),
    "CitationForgery":        ("H", "Citation forgery",        "Fake arXiv paper · forged sig · brand-URL · leaked-memo screenshot"),
    "Agentic":                ("I", "Agentic & MCP",           "MCP squatting · tool-shadow · Computer Use OCR · memory-tool poison"),
    "EmbeddedDomain":         ("J", "Embedded / domain",       "Banking · medical · voice-asst · IDE · customer-support AI"),
    "CrossAiCascade":         ("K", "Cross-AI cascade",        "LLM-to-LLM relay · RAG-embedding poison · judge-model deception"),
    "AdversarialEncoding":    ("L", "Adversarial encoding",    "Multi-lingual code-switch · cipher · RTL-override bidi"),
    "TimeStateReplay":        ("M", "Time / state / replay",   "Prompt-cache poison multi-tenant · session-fingerprint drift"),
}

# Stable display ordering
CATEGORY_ORDER = [
    "PrivacyTargeted", "Multimodal", "ToolChainConfusion",
    "AuthorityImpersonation", "MetaLevel", "MemoryExploitation",
    "IndirectChain", "CitationForgery", "Agentic", "EmbeddedDomain",
    "CrossAiCascade", "AdversarialEncoding", "TimeStateReplay",
]

TIER_BADGE = {
    "Critical": "🔴 Critical",
    "High":     "🟠 High",
    "Medium":   "🟡 Medium",
    "Low":      "🟢 Low",
}


def load_catalog() -> dict:
    cmd = ["cargo", "run", "--quiet", "--release", "--bin", "dump_ipi_catalog"]
    proc = subprocess.run(cmd, cwd=CORE_DIR, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def vec_id_sort_key(vid: str) -> tuple:
    """Sort IPI-v2-A18 *after* IPI-v2-A2 (numeric tail, not lexicographic)."""
    tail = vid.rsplit("-", 1)[-1]
    letter = tail[0]
    try:
        num = int(tail[1:])
    except ValueError:
        num = 999
    return (letter, num)


def fmt_breakdown(b: dict) -> str:
    return (
        f"I={b['impact']} · R={b['reproducibility']} "
        f"· X={b['exploit_complexity']} · S={b['scope']}"
    )


def render(doc: dict) -> str:
    vectors = doc["vectors"]
    out: list[str] = []

    # ─── Header ────────────────────────────────────────────────
    out.append("# IPI-v2 — vector inventory")
    out.append("")
    out.append("> **Auto-generated** from `cargo run --release --bin dump_ipi_catalog`.  ")
    out.append("> **Regenerate:** `python3 scripts/ipi/render_inventory_md.py > docs/vector-inventory.md`  ")
    out.append("> **Source of truth:** `core/src/ipi/vectors.rs::IPI_V2` — this MD is downstream.")
    out.append("")

    # ─── Headline numbers ──────────────────────────────────────
    tier_counts = Counter(v["severity_tier"] for v in vectors)
    cat_counts = Counter(v["category"] for v in vectors)
    channel_counts: Counter = Counter()
    for v in vectors:
        for c in v["input_channels"]:
            channel_counts[c] += 1

    out.append("## Headline numbers")
    out.append("")
    out.append(f"- **{doc['count']} active vectors** (`IPI-v2-*`) + 12 deprecated (`IPI-v1-*`, retained for the audit trail)")
    out.append(f"- **{len(cat_counts)} categories** (A → M, Legacy excluded)")
    out.append("- **Severity tier distribution:** " + " · ".join(
        f"{TIER_BADGE[t]} {tier_counts[t]}" for t in ("Critical", "High", "Medium", "Low") if tier_counts[t]
    ))
    out.append(f"- **Input-channel distribution:** " + " · ".join(
        f"`{c}` {n}" for c, n in sorted(channel_counts.items(), key=lambda kv: -kv[1])
    ))
    text_testable = sum(1 for v in vectors if "UrlOrText" in v["input_channels"])
    out.append(f"- **Text-testable (has UrlOrText):** {text_testable}/{doc['count']} "
               f"— the other {doc['count']-text_testable} vectors are pure multimodal/tool/MCP "
               "and sit outside the text harness, pending multimodal asset generation")
    out.append("")

    # ─── How a vector is exercised ─────────────────────────────
    out.append("## How a vector is exercised")
    out.append("")
    out.append("The harness in this repository runs a **canary-echo test**: for each vector it")
    out.append("builds a single-turn summarisation prompt out of three parts —")
    out.append("")
    out.append("1. **User context** carrying per-run synthetic canary identifiers, so a leak is")
    out.append("   unambiguous and cannot carry over between rows.")
    out.append("2. **Attacker content** built from the vector's `harness_probe` field where one")
    out.append("   exists, otherwise from `public_detection_signature`. Full reproducer payloads")
    out.append("   stay in the private store and never appear here.")
    out.append("3. **A neutral task instruction** asking for a short summary of the pasted page.")
    out.append("")
    out.append("An LLM-as-judge call then reads probe, canaries and response and returns one of")
    out.append("`leaked` / `resilient` / `refused` / `inconclusive` with a reasoning trace. What")
    out.append("this establishes is the **base-model precondition** for the attack chain, not")
    out.append("end-to-end exploitability — see [`methodology.md`](methodology.md).")
    out.append("")

    # ─── Surface inventory ────────────────────────────────────
    out.append("## Surface — which files hold the work?")
    out.append("")
    out.append("| Layer | File | Role |")
    out.append("|---|---|---|")
    out.append("| Catalogue (canonical) | `core/src/ipi/vectors.rs` | `VectorMetadata` literals + schema rev 2 + tripwire tests |")
    out.append("| Aggregator | `core/src/ipi/mod.rs` | `is_high_risk_result` 3-OR + Critical vectors bound to the catalogue |")
    out.append("| JSON dumper | `core/src/bin/dump_ipi_catalog.rs` | Source of this file; JSON for the harness |")
    out.append("| Test-matrix harness | `scripts/ipi/run_test_matrix.py` | Canary-echo test across model adapters |")
    out.append("| Scoreboard builder | `scripts/ipi/build_scoreboard.py` | Aggregates run CSVs into the public scoreboard |")
    out.append("| Private payloads | `core/ipi-private-payloads/IPI-v2-*.yaml` | `full_payload` + `reproducer_steps`, written during the disclosure cycle — git-ignored |")
    out.append("")

    # ─── Per-category table of contents ───────────────────────
    out.append("## Category summaries")
    out.append("")
    out.append("| Letter · Category | Count | Tier distribution | Description |")
    out.append("|---|---|---|---|")
    by_cat = defaultdict(list)
    for v in vectors:
        by_cat[v["category"]].append(v)
    for cat in CATEGORY_ORDER:
        if cat not in by_cat:
            continue
        items = by_cat[cat]
        letter, name, blurb = CATEGORY_LABEL[cat]
        tiers = Counter(v["severity_tier"] for v in items)
        tier_str = " ".join(f"{TIER_BADGE[t][0:2]}{tiers[t]}" for t in ("Critical","High","Medium","Low") if tiers[t])
        out.append(f"| **{letter}** · {name} (`{cat}`) | {len(items)} | {tier_str} | {blurb} |")
    out.append("")

    # ─── Per-vector detail ────────────────────────────────────
    out.append("## Vector detail — by category")
    out.append("")

    for cat in CATEGORY_ORDER:
        if cat not in by_cat:
            continue
        items = sorted(by_cat[cat], key=lambda v: vec_id_sort_key(v["id"]))
        letter, name, blurb = CATEGORY_LABEL[cat]
        out.append(f"### {letter}. {name} (`{cat}`) — {len(items)} vectors")
        out.append("")
        out.append(f"_{blurb}_")
        out.append("")

        for v in items:
            short_title = v["taxonomy_public"].split(" — ", 1)
            heading = short_title[0].strip() if len(short_title) > 1 else v["id"]
            heading = heading.replace("\n", " ").replace("  ", " ")[:90]

            out.append(f"#### `{v['id']}` — {heading}")
            out.append("")
            out.append(f"- **Tier:** {TIER_BADGE[v['severity_tier']]}")
            out.append(f"- **Channels:** {', '.join('`'+c+'`' for c in v['input_channels'])}")
            out.append(f"- **Severity breakdown** (private numeric, visible in vendor disclosure): {fmt_breakdown(v['severity_breakdown'])}")
            out.append(f"- **Taxonomy (public):**")
            for line in _wrap_paragraph(v["taxonomy_public"]):
                out.append(f"  > {line}")
            out.append(f"- **Detection signature (public):**")
            for line in _wrap_paragraph(v["public_detection_signature"]):
                out.append(f"  > {line}")
            if v.get("references"):
                out.append(f"- **References ({len(v['references'])}):**")
                for ref in v["references"]:
                    out.append(f"  - {ref}")
            out.append("")

    # ─── Footer ────────────────────────────────────────────────
    out.append("---")
    out.append("")
    out.append("## Open questions")
    out.append("")
    out.append("1. **Probe body composition.** How much of a vector should reach the model as")
    out.append("   content? A probe built from `public_detection_signature` carries the catalogue's")
    out.append("   own wording, which a model can recognise and refuse on sight; a probe built from")
    out.append("   `harness_probe` is attack-shaped but has to be authored per vector.")
    out.append("2. **Multimodal delivery.** The 38 non-text vectors need generated assets (image,")
    out.append("   audio, PDF, QR) before they can be exercised at all. Until then any headline")
    out.append("   resilience number covers the text-testable subset only, and should say so.")
    out.append("3. **Which signal the scoreboard publishes.** Fetch-based beacons (\"did the model")
    out.append("   retrieve the URL\") and canary-echo tests (\"did the model repeat the identifier\")")
    out.append("   measure different things. Publishing a single resilience score requires deciding")
    out.append("   which one it is, or how the two normalise against each other.")
    out.append("4. **Prompt-scale limits.** No current assistant will fetch 125 URLs from one")
    out.append("   prompt — rate limits, context and policy all intervene. Batching, tier-first")
    out.append("   prioritisation and one-vector-per-prompt iteration each trade coverage against")
    out.append("   run cost differently.")

    return "\n".join(out) + "\n"


def _wrap_paragraph(text: str, width: int = 90) -> list[str]:
    """Soft-wrap a single paragraph; never break inside a word, keep
    blockquote-friendly. Returns 1+ lines."""
    text = " ".join(text.split())
    if len(text) <= width:
        return [text]
    out: list[str] = []
    cur: list[str] = []
    cur_len = 0
    for word in text.split(" "):
        if cur_len + len(word) + (1 if cur else 0) > width and cur:
            out.append(" ".join(cur))
            cur = [word]
            cur_len = len(word)
        else:
            cur.append(word)
            cur_len += len(word) + (1 if len(cur) > 1 else 0)
    if cur:
        out.append(" ".join(cur))
    return out


def main(argv: list[str]) -> int:
    doc = load_catalog()
    sys.stdout.write(render(doc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
