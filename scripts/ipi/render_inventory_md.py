#!/usr/bin/env python3
"""
render_inventory_md.py — render the IPI-v2 catalog as a single
human-readable Markdown inventory.

Source of truth: `cargo run --release --bin dump_ipi_catalog` (the
same canonical 100-vector JSON the test-matrix harness consumes).
The MD never lives in vectors.rs — running this script regenerates it
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
from datetime import datetime, timezone
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

# Stable display ordering (matches PLAN doc batch sequence)
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
    out.append(f"> **Snapshot:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
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
    out.append(f"- **{doc['count']} active vectors** (`IPI-v2-*`) + 12 deprecated (`IPI-v1-*`, date archive only)")
    out.append(f"- **{len(cat_counts)} categories** (A → M, Legacy excluded)")
    out.append("- **Severity tier distribution:** " + " · ".join(
        f"{TIER_BADGE[t]} {tier_counts[t]}" for t in ("Critical", "High", "Medium", "Low") if tier_counts[t]
    ))
    out.append(f"- **Input-channel distribution:** " + " · ".join(
        f"`{c}` {n}" for c, n in sorted(channel_counts.items(), key=lambda kv: -kv[1])
    ))
    text_testable = sum(1 for v in vectors if "UrlOrText" in v["input_channels"])
    out.append(f"- **Text-testable (has UrlOrText):** {text_testable}/{doc['count']} "
               f"— the other {doc['count']-text_testable} vectors are pure multimodal/tool/MCP, "
               "outside Step 7 harness V1 (waiting on asset-gen pickup #7)")
    out.append("")

    # ─── How a vector works today ──────────────────────────────
    out.append("## How a vector works — today's reality (at code level)")
    out.append("")
    out.append("**3-stage honeypot pipeline:**")
    out.append("")
    out.append("1. **Token issue.** `POST aitest.github.com/ersincivi/v1/ipi/issue-token`")
    out.append("   → the server generates 100 vectors × 1 URL: `https://aitest.github.com/ersincivi/probe/<token>/<vec_id>`")
    out.append("2. **AI fetch.** The user pastes the 100-URL markdown list into ChatGPT/Claude/Gemini;")
    out.append("   if the AI fetches the URLs the server's `serve_probe(...)` GET handler is triggered,")
    out.append("   and a 300-second memory-only event is written to `IpiStore` (`user_agent` + `ip_hash`).")
    out.append("3. **Result poll.** App `POST /v1/ipi/result/<token>` → triggered vector list +")
    out.append("   resilience score 0-100 (formula: `100 * (1 - triggered/total)`).")
    out.append("")
    out.append("**Per-vector body — current state (gap):**")
    out.append("")
    out.append("- The `/probe/:t/:v` endpoint returns **a single generic honeypot template** via `vector_page_html(vector_id, token, callback_base)` — the body is the same for every vector, only the `<meta name=\"ipi-vector\" content=\"...\">` tag differs.")
    out.append("- So what is being tested right now is: **\"how many of the 100 URLs does the AI actually GET?\"** — the vector's specific content (taxonomy_public / public_detection_signature) is **NOT** included in the probe body.")
    out.append("- **Multi-channel routes (shipped 2026-05-19):** `vectors_b.rs` added 6 endpoints (`/probe/:t/:v/svg` real inline-generated B10 SVG injection + 5 asset-stub 503 channels). But the in-app prompt keeps listing the 100 generic `/probe/:t/:v` URLs and does **not use** these enriched channels.")
    out.append("- **Step 7 harness (V1 in this session):** a separate methodology — a per-vector canary echo test using the user's own LLM API key. Completely independent of the in-app honeypot beacon. Which metric the public scoreboard will publish — **decision open**.")
    out.append("")

    # ─── Surface inventory ────────────────────────────────────
    out.append("## Surface — which files hold the work?")
    out.append("")
    out.append("| Layer | File | Role |")
    out.append("|---|---|---|")
    out.append("| Catalogue (canonical) | `core/src/ipi/vectors.rs`, ~4000 lines | `VectorMetadata` literals + schema rev 2 + tripwire tests |")
    out.append("| Catalogue (server mirror, ID-only) | server-side | String ID list only; no per-vector metadata on the server |")
    out.append("| Multi-channel routes | server-side | 6 endpoints: 1 real SVG (B10) + 4 asset stubs + 1 QR stub |")
    out.append("| Honeypot store | server-side | 300 s memory-only, 5 s reaper, no disk |")
    out.append("| Aggregator | `core/src/ipi/mod.rs` | `is_high_risk_result` 3-OR + Critical vectors bound to the catalogue |")
    out.append("| Private payloads | `core/ipi-private-payloads/IPI-v2-*.yaml` | Stubs; full_payload + reproducer_steps are written during the disclosure cycle — git-ignored |")
    out.append("| Client catalogue string list | client-side | 112 strings (12 legacy + 100), used only as the resilience-score denominator |")
    out.append("| iOS prompt composer | `ios/IPI/Views/IpiTestCardView.swift::composePrompt` | The 100 URLs in a single markdown bullet list |")
    out.append("| JSON dumper | `core/src/bin/dump_ipi_catalog.rs` | Source of this MD; JSON for the harness |")
    out.append("| Step 7 harness | `scripts/ipi/run_test_matrix.py` | Offline canary-echo test (V1: mock + Claude) |")
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
    out.append("## To be discussed together — 4 architectural questions")
    out.append("")
    out.append("Layers we want clarity on before this doc is closed:")
    out.append("")
    out.append("1. **Test methodology integrity:** the in-app honeypot beacon (\"did the AI fetch the URL\") and the Step 7 harness (\"did the AI echo the canary\") are two separate signals. If the IPI public scoreboard is to publish a single resilience score, which one? Both? How to normalise?")
    out.append("2. **Per-vector payload delivery:** the `/probe/:t/:v` body is a generic template today. Should `taxonomy_public` + `public_detection_signature` be served in the body? Or should they be injected inside the in-app prompt (no URL, single prompt)? How do the multi-channel SVG/PDF routes enter the prompt?")
    out.append("3. **100-URL bottleneck:** ChatGPT/Claude will not fetch 100 URLs in a single prompt (rate/context/policy). Strategies: (a) batching — 10 URLs × 10 rounds, (b) prioritisation — Critical-19 + curated High first, \"expand\" if the user wants, (c) per-vector one-shot prompt + manual iteration.")
    out.append("4. **In-app vs offline harness authority boundary:** the in-app test is the user surface (free, no API key, coarse). The offline harness is internal R&D (paid, fine-grained). Should this split be visible on the public scoreboard (\"Beacon Score X / Echo Score Y\")? Or is Beacon always public and Echo private?")
    out.append("")
    out.append("Moving to Step 7 LIVE RUN or Step 8 disclosure tooling before these 4 questions are locked is premature.")

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
