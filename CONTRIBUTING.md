# Contributing to IPI

Thanks for considering a contribution. IPI is a small
single-maintainer project today; community contributions in the
following areas are particularly welcome:

## High-value contribution areas

### 1. Vector proposals (new attacker-shape categories)

If you've observed a real-world indirect-prompt-injection vector that
isn't in the current catalogue, propose it via GitHub Issue using the
"Vector proposal" template (or open an Issue if the template doesn't
exist yet).

Per-vector proposals should include:
- **Public taxonomy** — 1-2 sentence description (vendor-agnostic)
- **Public detection signature** — what the attacker page looks like
  on inspection
- **Threat model** — what real-world surface this informs
  (wallet UI / EHR scribe / PR-review pipeline / etc.) — described as
  threat-model context, not as an end-to-end validation claim
- **Severity profile** — Impact / Reproducibility /
  Exploit_Complexity / Scope axis scores (0-4) with brief
  justifications

We will not accept private payload / reproducer content in public
Issues (that lives in the operator-side private payload store and is
authored only as part of a coordinated disclosure cycle).

### 2. Harness improvements

Adapter additions for new vendors, judge classifier improvements,
catalog version migrations, output format additions, etc. Open a PR
with:
- Clear description of what the change does
- Tests where applicable (smoke tests against `mock` adapter at
  minimum)
- README / docs update if user-facing

### 3. Methodology audits

IPI's V3 judge classifier reliability has not yet been audited at a
statistically significant sample size. We welcome:
- Inter-rater reliability comparisons (human vs Claude Haiku judge)
- Confidence calibration studies
- Heuristic-vs-judge divergence analysis

### 4. Translations / localisations

IPI methodology docs in non-English / non-DACH languages help reach
consumers outside the project's home region. PRs for translations of
`docs/methodology.md` and `README.md` welcome.

## Contribution policy

### What we accept

- Vector proposals (public taxonomy only — see above)
- Harness code changes (with tests)
- Documentation improvements
- Bug reports for the harness / catalog
- Methodology audit contributions

### What we do not accept

- **IPI-class findings against vendors** posted as public Issues
  (use the coordinated disclosure channel in
  [`SECURITY.md`](SECURITY.md) instead)
- **Direct prompt injection / jailbreak / alignment debate** content
  (out of IPI scope — see [`docs/methodology.md`](docs/methodology.md))
- **Private payload / reproducer text** in public Issues / PRs
  (private payload store is operator-side)
- **End-to-end exploit proof-of-concept** against named vendor
  production surfaces (IPI measurement stops at the base-model
  precondition)

## Code style

### Rust (core/)

- Format: `cargo fmt`
- Lint: `cargo clippy -- -D warnings`
- Test: `cargo test`

### Python (scripts/ipi/)

- Python ≥ 3.10
- Format: `ruff format` (no Black)
- Lint: `ruff check`
- Type hints encouraged but not enforced
- Test: smoke `python3 scripts/ipi/run_test_matrix.py --models mock`

### Documentation

- Markdown wrapping: prefer flow text over hard wraps (no 80-column
  hard wrap; let the renderer wrap)
- Reference vectors as `` `IPI-v2-X` `` (backticked)
- Reference catalog version (currently `IPI-v2`) when stating
  vector counts or severity distributions

## PR review process

Solo maintainer review. Expect:
- Initial response within 14 calendar days (often faster)
- Substantive review feedback inline on PR
- Approval requires passing CI (when CI exists) + maintainer review

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
Participation in this repository (Issues, PRs, Discussions if enabled)
implies agreement.

## License

By contributing, you agree your contributions will be licensed under
the [Apache-2.0 License](LICENSE).

— IPI maintainer (via GitHub)
