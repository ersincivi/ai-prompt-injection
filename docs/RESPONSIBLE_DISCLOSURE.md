# IPI Responsible Disclosure Policy

> This document describes how the IPI project handles IPI-class
> findings when reporting them to affected vendors. For the
> reverse — how to report security findings against IPI itself —
> see [`SECURITY.md`](../SECURITY.md).

## Cycle overview

IPI follows a **coordinated disclosure cycle** with affected
vendors. The default cycle is:

```
T+0          → Vendor notified via PGP-encrypted email to their
                 published security contact (security.txt / CVD page).
T+0..T+14    → Vendor acknowledgement window. If no ack by T+14,
                 a polite reminder is sent on the same thread.
T+0..T+90    → Embargo period. Public scoreboard row is redacted as
                 <redacted-pending-disclosure>. No public mention of
                 the finding outside of meta-discussion that does not
                 attribute the finding to the vendor.
T+90         → Embargo end. Public scoreboard row appears with vendor
                 name. IPI Bulletin issue is prepared if findings
                 meet bulletin-publication threshold.
```

The 90-day standard reflects the industry-norm Coordinated
Vulnerability Disclosure (CVD) timeline. Per-category overrides
(shorter or longer) are documented in §5 below.

## What we send to the vendor

The per-vendor disclosure packet contains:

1. **Public catalog metadata** — per-vector taxonomy, detection
   signature, severity breakdown (4-axis profile), holistic tier
2. **Private payload + reproducer** — per-vector `full_payload`
   (with variants), `reproducer_steps`, `internal_breakdown_
   justification` (4-axis with prose justifications)
3. **Observed behaviour** — heuristic verdict + judge verdict +
   judge reasoning + judge confidence + latency, per leaked row
4. **Test-surface caveat** (where applicable) — explicit note for
   vectors tested via system-prompt-simulated environments rather
   than the named production surface
5. **Suggested remediation patterns** — vendor-agnostic, pattern-
   level hints. We do not prescribe vendor-specific infrastructure
   changes.
6. **Methodology framing** — full [`methodology.md`](methodology.md)
   §1-§3 (scope of measurement, what IPI does NOT test, reading
   tier labels) inlined in the packet's §3, so the disclosure is
   self-contained.

The packet is **PGP-encrypted** to the vendor's published security
key (recipient UID-match verified against the email address). The
encrypted artefact is delivered via the vendor's stated channel
(email / portal / bug-bounty intake, as the vendor prefers).

## What the vendor receives in plain text (cover note)

Plain-text cover (sent alongside the PGP attachment for indexing /
ack):

- IPI cycle identifier (`2026-Q2-<vendor>`)
- Findings count + severity split
- Embargo end date
- Reporter contact (a private security advisory on this repository + PGP fingerprint)
- Brief description that the attached `.asc` is PGP-encrypted under
  the vendor's published key

We do **not** put per-finding details in the plain-text cover —
those live inside the encrypted attachment.

## What we ask the vendor to do

1. **Acknowledge the receipt** within ~14 days of notification.
2. **Investigate** the findings through the vendor's internal
   pipeline-team channels (IPI measurement stops at the base-model
   precondition; end-to-end production exploitability requires the
   vendor's own pipeline-side investigation).
3. **Optionally**: ship hardening / patches before embargo end. If
   patches ship, please let us know — we record `fix-shipped` dates
   in our `vendor_response_history` ledger and the public scoreboard
   reflects the patched-vs-pending state when embargo lapses.
4. **Optionally**: indicate if your CVD policy treats IPI-class
   findings as eligible for your hall-of-fame / bug-bounty
   programme. If so, we'd appreciate the link or scope clarification
   so future the IPI project submissions route through the
   appropriate channel.

## What we will NOT do

- We will **not** publish vendor-specific findings before the
  embargo period ends.
- We will **not** share embargoed findings with third parties.
- We will **not** attempt to exploit end-to-end attack chains in
  production vendor systems — IPI measurement scope stops at the
  base-model precondition.
- We will **not** modify the disclosure schedule to favour or
  penalise specific vendors. The 90-day cycle is uniform.
- We will **not** put IPI-class findings in our scoreboard or
  Bulletin without first running them through this disclosure
  cycle.

## Per-category embargo overrides

Most catalog categories follow the 90-day standard. Two overrides
are documented:

- **Banking / healthcare embedded-AI findings** (vector categories
  `J1` banking + `J2` healthcare): a **7-day Live disclosure cycle**
  may apply where the finding indicates an active production
  exploitation risk in a deployed banking-AI or healthcare-AI
  surface. Triggered case-by-case; default remains 90-day.
- **Consumer-facing AI assistant findings** with active production
  exploitation evidence: **72-hour Live** consideration applies. As
  above, the default remains 90-day; the 72-hour path requires
  evidence of active exploitation in the wild.

In both override cases, the IPI team consults with the affected
vendor on the appropriate timeline before locking the embargo
schedule.

## Public artefact lifecycle (Day-0)

At embargo end (per-vendor "Day-0"):

1. **Scoreboard row publishes** with vendor name, leaked vector
   list, judge confidence, fix-shipped status
2. **IPI Bulletin issue** (if multiple findings or methodology
   notes warrant) is published on the project blog / repo issues
3. **Per-vendor private payload** transitions to public-archive
   state (the `harness_probe` text is published; the
   `internal_breakdown_justification` may remain private or
   publish at the maintainer's discretion)
4. **Vendor response history** field in the scoreboard reflects
   the acknowledged date, fix-shipped date, fix-verified date (if
   the vendor confirms and we re-test)

## How IPI tracks responses

Per-vector YAML records in the maintainer-side private store carry a
`vendor_response_history` field:

```yaml
vendor_response_history:
  - vendor: <vendor-id>
    notified: YYYY-MM-DD
    embargo_end: YYYY-MM-DD
    acknowledged: YYYY-MM-DD
    fix_shipped: YYYY-MM-DD
    fix_verified: YYYY-MM-DD
```

These records ship as part of the scoreboard row when embargo
lapses. Vendor names are recorded only after a coordinated
disclosure cycle has completed for that vector + vendor pair.

## Reporter behaviour expectations

If you are a security researcher who discovers an IPI-class
finding independently, the recommended workflow is documented in
[`SECURITY.md`](../SECURITY.md) §"Reporting IPI-class findings".
Highlights:

1. Send the finding **directly to the vendor** via their published
   CVD contact under their stated embargo window.
2. **Optional**: mirror a copy to a private security advisory on this repository if you
   want the finding considered for the next IPI scoreboard cycle.
   We respect the same vendor embargo as you do.

## Contact

a private security advisory on this repository · PGP `3386 802D 7247 402A B3F6 CDA7 6199
7B93 21E9 49AE` ([key on keys.openpgp.org](https://keys.openpgp.org/search?q=security%40github.com/ersincivi))

— the IPI project · solo individual-developer project at
[github.com/ersincivi](https://github.com/ersincivi)
