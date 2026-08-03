# Security policy — IPI testbed

## Reporting vulnerabilities **in this repository** (harness / catalog / scripts)

If you find a security issue in the IPI codebase itself (not an
IPI-class finding against a vendor), please report privately:

- **Email**: a private security advisory on this repository
- **PGP**: `3386 802D 7247 402A B3F6 CDA7 6199 7B93 21E9 49AE`
  ([key on keys.openpgp.org](https://keys.openpgp.org/search?q=security%40github.com/ersincivi))
- **Response SLA**: Initial acknowledgement within 14 calendar days.
- **Disclosure timeline**: Coordinated with the reporter; default
  90-day embargo from acknowledgement.

Please **do not** open public GitHub Issues for codebase security
findings.

## Reporting IPI-class findings (a vendor model leaked under V3 framing)

If you discover an IPI-class finding against a vendor model
(indirect prompt injection causing canary echo / attacker-instruction
follow / data exfiltration), the recommended channels are:

1. **The vendor's published Coordinated Vulnerability Disclosure
   contact** (usually listed in the vendor's `security.txt` or bug
   bounty programme rules). Send your finding there under the
   vendor's published embargo window.

2. **Mirror a copy to** a private security advisory on this repository (optional) if you
   want the finding considered for the next IPI scoreboard cycle.
   We respect the same vendor embargo as you do — your mirror copy
   is not published until the embargo lapses on the vendor's
   timeline.

We do **not** accept IPI-class findings to be published outside the
vendor's coordinated-disclosure cycle. Public-disclosure-only reports
are out of scope.

## Out of scope

- Findings against **direct** prompt injection (jailbreaks, alignment
  debates, content-policy disagreements). IPI's measurement scope is
  *indirect* prompt injection via page-content directive framing only.
- Findings that depend on running modified harness code outside the
  published V3 framing.
- Findings against products / surfaces IPI does not test
  (end-to-end exploitability in wallet / healthcare / PR-review /
  cache integrations — those are the threat models IPI findings
  *inform*, not validate).

## Disclosure cycle policy

IPI follows a coordinated disclosure cycle when reporting findings to
vendors. The full policy lives in
[`docs/RESPONSIBLE_DISCLOSURE.md`](docs/RESPONSIBLE_DISCLOSURE.md).

Highlights:

- **90-day embargo** from notification to public scoreboard release
  (standard CVD norm).
- **Per-vendor packet** with public taxonomy + private payload +
  reproducer + suggested remediation patterns (vendor-agnostic).
- **PGP-encrypted delivery** to the vendor's published security
  contact.
- **Scoreboard row redacted** as `<redacted-pending-disclosure>` until
  the embargo lapses; per-vendor names appear in the public scoreboard
  only after embargo end.
- **Vendor response history tracked** in private YAMLs (acknowledged
  date, fix-shipped date) — published as part of the scoreboard row.

## What we will not do

- We will not **publish** IPI-class findings before the vendor's
  embargo period ends.
- We will not **share** vendor-specific findings with third parties
  outside the embargo.
- We will not **disclose** the reporter's identity in scoreboard rows
  or public communications without explicit reporter consent.
- We will not **attempt to exploit** end-to-end attack chains in
  production vendor systems — IPI measurement stops at the
  base-model precondition.

## Hall of fame

IPI maintains a public hall of fame for contributors whose findings
or harness improvements land in the catalogue. Inclusion is opt-in.

— IPI maintainer (via GitHub)
