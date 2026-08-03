# IPI Per-Vendor Public Scoreboard

> **Auto-generated.** Regenerate with
> `python3 scripts/ipi/build_scoreboard.py`.
>
> This scoreboard publishes per-vendor base-model resilience profiles
> for the IPI-v2 catalogue vector tests. Per-vendor rows appear only
> **after** the per-vendor coordinated-disclosure embargo lapses.
> Until embargo end, the corresponding row is redacted.
>
> See [`methodology.md`](methodology.md) §3 "Reading tier labels" for
> how to read the verdict columns — `Critical` here means
> *"base-model precondition severity is strong"*, not
> *"end-to-end attack chain works in production"*.

---

## Public release status (placeholder pre-Day-0)

This file is committed in its **pre-Day-0** state. Per-vendor rows
that are still within their coordinated-disclosure embargo window
appear as `<redacted-pending-disclosure>`. As each vendor embargo
lapses, the corresponding scoreboard row updates with the real
vendor name + finding profile + acknowledgement / fix-shipped /
fix-verified dates.

## How rows update

The `build_scoreboard.py` script reads:

- `scripts/ipi/results/*.csv` — V3 harness run outputs (local, not committed in this public repo)
- `core/ipi-private-payloads/<vec_id>.yaml::vendor_response_history`
  — per-vector vendor disclosure ledger (private until embargo lapses)

… and emits the public-safe view: vendor names redacted while
embargo holds, named once embargo lapses.

## Tier label reading reminder

| Tier | Means |
|---|---|
| `Critical` | Base-model precondition is strong (high Impact, deterministic reproducibility, low exploit complexity, broad scope of base-model surface). |
| `High` | Solid base-model precondition; one axis weaker than Critical. |
| `Medium` | Partial precondition; significant axis weaknesses. |
| `Low` | Weak precondition or substantial test-surface caveats. |

**A `Critical` tier in this scoreboard does NOT mean the attack
works end-to-end in production wallet / healthcare / PR-review /
cache systems.** See [`methodology.md`](methodology.md) for the
demonstrated-vs-informed boundary.

## Vendor response notation

| Status | Meaning |
|---|---|
| `notified` | Initial PGP-encrypted disclosure sent to vendor's published CVD contact |
| `acknowledged` | Vendor confirmed receipt + intake routing |
| `fix-shipped` | Vendor shipped mitigation / model update / pipeline hardening |
| `fix-verified` | IPI re-tested post-fix and confirmed resilience improvement |

---

## Aggregate snapshot

*This section auto-regenerates from `build_scoreboard.py`. Pre-Day-0
state shows no vendor rows; aggregate counts reflect total V3
harness coverage across the catalog.*

- **Catalog scope**: IPI-v2 (125 vectors, 13 categories)
- **V3 text-testable subset**: 87 vectors
- **Vendor disclosure cycles in progress**: (redacted until embargo lapses)
- **Vendor disclosure cycles closed** (embargo lapsed): 0
- **Public scoreboard rows ready for publication**: 0

---

## Per-vendor rows

*Empty pre-Day-0. Rows populate as embargoes lapse.*

| Vendor | Model | Run ID | Vectors tested | Resilient | Leaked | Refused | Inconclusive | Acknowledged | Fix shipped |
|---|---|---|---|---:|---:|---:|---:|---|---|
| `<redacted-pending-disclosure>` | `<redacted>` | `<redacted>` | – | – | – | – | – | – | – |

*One row per per-vendor disclosure cycle. Cycles in flight today
redacted; rows above are placeholders for `build_scoreboard.py` to fill in as embargo end dates arrive.*

---

## Per-vector aggregate (across published vendor rows only)

*Empty pre-Day-0. Aggregate appears once at least one per-vendor
embargo has lapsed and the corresponding vendor row publishes.*

---

## Reading this file

If you arrived here from a per-vendor disclosure packet's §0 "At a
glance" table or §5 "How to respond" reference, this file is the
canonical public scoreboard surface where your vendor row appears
**after** the embargo end date stated in your packet.

Until then:

- Your packet's findings are private between you and the IPI
  reporter
- This public file does not name your vendor
- The corresponding YAML records in our maintainer-side store carry
  your `notified` / `acknowledged` / `fix-shipped` / `fix-verified`
  dates; these dates appear in your scoreboard row at embargo end

If your vendor team wants to indicate progress before embargo end
(acknowledged status, in-flight fix, request for embargo extension),
the contact channel is the existing per-vendor email thread (or
a private security advisory on this repository for new outreach).

---

— IPI maintainer (via GitHub) · Apache-2.0 ·
[github.com/ersincivi/ai-prompt-injection](https://github.com/ersincivi/ai-prompt-injection)
