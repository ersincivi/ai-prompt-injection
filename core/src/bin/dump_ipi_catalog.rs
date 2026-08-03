//! Dump the active IPI-v2 catalog as JSON to stdout.
//!
//! Canonical data source for offline tooling (the test-matrix
//! harness, vendor disclosure packet builders, scoreboard generators).
//! Reading the Rust catalog directly avoids the drift risk of a
//! parallel JSON file.
//!
//! Usage:
//!   cargo run --quiet --release --bin dump_ipi_catalog
//!
//! Emits a JSON document with shape:
//!   { schema_version: 2, series: "IPI-v2", count: 100, vectors: [...] }
//!
//! Each vector entry is the public surface of `VectorMetadata` —
//! `severity_breakdown` is included because the numeric axes alone
//! aren't a working exploit. Private payload strings,
//! reproducer steps, and vendor response history live in
//! `core/ipi-private-payloads/<id>.yaml` (git-ignored) and are NOT
//! emitted here.

use ipi_testbed::ipi::vectors::{
    InputChannel, SeverityTier, VectorCategory, VectorMetadata, VectorSeries, IPI_V2,
};
use serde_json::json;

fn main() {
    let vectors: Vec<serde_json::Value> = IPI_V2.iter().map(vector_to_json).collect();

    let doc = json!({
        "schema_version": 2,
        "series": "IPI-v2",
        "count": vectors.len(),
        "vectors": vectors,
    });

    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

fn vector_to_json(v: &VectorMetadata) -> serde_json::Value {
    json!({
        "id": v.id,
        "series": series_str(v.series),
        "category": category_str(v.category),
        "severity_tier": severity_str(v.severity_tier),
        "severity_breakdown": {
            "impact": v.severity_breakdown.impact,
            "reproducibility": v.severity_breakdown.reproducibility,
            "exploit_complexity": v.severity_breakdown.exploit_complexity,
            "scope": v.severity_breakdown.scope,
        },
        "taxonomy_public": v.taxonomy_public,
        "public_detection_signature": v.public_detection_signature,
        "announcement_template": v.announcement_template,
        "references": v.references,
        "input_channels": v
            .input_channels
            .iter()
            .map(|c| channel_str(*c))
            .collect::<Vec<_>>(),
        "deprecated": v.deprecated,
    })
}

fn series_str(s: VectorSeries) -> &'static str {
    match s {
        VectorSeries::IpiV1 => "IpiV1",
        VectorSeries::IpiV2 => "IpiV2",
    }
}

fn category_str(c: VectorCategory) -> &'static str {
    match c {
        VectorCategory::Legacy => "Legacy",
        VectorCategory::PrivacyTargeted => "PrivacyTargeted",
        VectorCategory::Multimodal => "Multimodal",
        VectorCategory::ToolChainConfusion => "ToolChainConfusion",
        VectorCategory::AuthorityImpersonation => "AuthorityImpersonation",
        VectorCategory::MetaLevel => "MetaLevel",
        VectorCategory::MemoryExploitation => "MemoryExploitation",
        VectorCategory::IndirectChain => "IndirectChain",
        VectorCategory::CitationForgery => "CitationForgery",
        VectorCategory::Agentic => "Agentic",
        VectorCategory::EmbeddedDomain => "EmbeddedDomain",
        VectorCategory::CrossAiCascade => "CrossAiCascade",
        VectorCategory::AdversarialEncoding => "AdversarialEncoding",
        VectorCategory::TimeStateReplay => "TimeStateReplay",
    }
}

fn severity_str(t: SeverityTier) -> &'static str {
    match t {
        SeverityTier::Low => "Low",
        SeverityTier::Medium => "Medium",
        SeverityTier::High => "High",
        SeverityTier::Critical => "Critical",
    }
}

fn channel_str(c: InputChannel) -> &'static str {
    match c {
        InputChannel::UrlOrText => "UrlOrText",
        InputChannel::Pdf => "Pdf",
        InputChannel::Image => "Image",
        InputChannel::Audio => "Audio",
        InputChannel::Video => "Video",
        InputChannel::McpResponse => "McpResponse",
        InputChannel::ToolResult => "ToolResult",
        InputChannel::ScreenshotOcr => "ScreenshotOcr",
        InputChannel::EmbeddedEmail => "EmbeddedEmail",
    }
}
