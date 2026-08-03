//! IPI — indirect prompt injection
//!
//! Public taxonomy + V3 testing harness for indirect prompt-injection
//! vector cataloguing. IPI measures **base-model behavioural
//! resilience under page-content directive framing** — not end-to-end
//! exploitability in named real-world surfaces.
//!
//! See [`ipi::vectors`] for the public catalog (125 vectors × 13
//! categories), and `docs/methodology.md` for the full
//! demonstrated-vs-informed framing.
//!
//! ## Catalog snapshot
//!
//! - **IPI-v2** — 125 vectors, 13 categories
//! - **Severity distribution**: 24 Critical · 64 High · 34 Medium · 3 Low
//! - **Text-testable subset (V3 covers this today)**: 87 vectors
//! - **Multimodal subset** (image / audio / PDF / OCR / agentic tool
//!   result): 38 vectors (pending the multimodal asset-generation
//!   sprint)
//!
//! ## Usage
//!
//! Dump the catalog as JSON:
//!
//! ```no_run
//! # // Run from the crate root:
//! # // cargo run --bin dump_ipi_catalog
//! ```
//!
//! Or programmatically:
//!
//! ```
//! use ipi_testbed::ipi::vectors::IPI_V2;
//! let active_count = IPI_V2.iter().filter(|v| !v.deprecated).count();
//! assert!(active_count >= 100);
//! ```
//!
//! ## Provenance
//!
//! This crate is the public taxonomy slice of the IPI project's
//! IPI testbed. The private payload reproducers (per-vector
//! `full_payload` + `reproducer_steps` + `internal_breakdown_
//! justification`) live in an operator-side private store and are
//! authored only as part of coordinated disclosure cycles with
//! affected vendors; they are not part of this public crate.

pub mod ipi;
