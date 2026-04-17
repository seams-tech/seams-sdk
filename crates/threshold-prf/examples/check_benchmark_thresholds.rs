use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CRITERION_GROUP: &str = "threshold_prf";

const THRESHOLDS: &[BenchmarkThreshold] = &[
    BenchmarkThreshold {
        name: "generate_signing_root",
        max_upper_bound_ns: 100_000.0,
    },
    BenchmarkThreshold {
        name: "split_signing_root_2_of_3",
        max_upper_bound_ns: 100_000.0,
    },
    BenchmarkThreshold {
        name: "evaluate_direct_reference",
        max_upper_bound_ns: 1_000_000.0,
    },
    BenchmarkThreshold {
        name: "evaluate_partial",
        max_upper_bound_ns: 1_000_000.0,
    },
    BenchmarkThreshold {
        name: "combine_partials",
        max_upper_bound_ns: 1_000_000.0,
    },
    BenchmarkThreshold {
        name: "option_a_evaluate_two_partials_and_combine",
        max_upper_bound_ns: 2_000_000.0,
    },
    BenchmarkThreshold {
        name: "derive_output_from_signing_root_shares",
        max_upper_bound_ns: 2_000_000.0,
    },
    BenchmarkThreshold {
        name: "evaluate_partial_with_dleq_proof",
        max_upper_bound_ns: 2_000_000.0,
    },
    BenchmarkThreshold {
        name: "verify_partial_dleq_proof",
        max_upper_bound_ns: 2_000_000.0,
    },
    BenchmarkThreshold {
        name: "refresh_signing_root_shares_2_of_3",
        max_upper_bound_ns: 1_000_000.0,
    },
];

#[derive(Debug)]
struct BenchmarkThreshold {
    name: &'static str,
    max_upper_bound_ns: f64,
}

#[derive(Debug, Deserialize)]
struct Estimates {
    mean: Estimate,
}

#[derive(Debug, Deserialize)]
struct Estimate {
    confidence_interval: ConfidenceInterval,
}

#[derive(Debug, Deserialize)]
struct ConfidenceInterval {
    upper_bound: f64,
}

fn main() {
    let mut failures = Vec::new();
    for threshold in THRESHOLDS {
        match check_threshold(threshold) {
            Ok(()) => {}
            Err(error) => failures.push(error),
        }
    }

    if failures.is_empty() {
        println!(
            "all {} threshold-prf native benchmark thresholds passed",
            THRESHOLDS.len()
        );
        return;
    }

    for failure in &failures {
        eprintln!("{failure}");
    }
    std::process::exit(1);
}

fn check_threshold(threshold: &BenchmarkThreshold) -> Result<(), String> {
    let estimates = read_estimates(threshold.name)?;
    let upper_bound_ns = estimates.mean.confidence_interval.upper_bound;
    if upper_bound_ns <= threshold.max_upper_bound_ns {
        println!(
            "ok: {} mean upper bound {} <= {}",
            threshold.name,
            format_ns(upper_bound_ns),
            format_ns(threshold.max_upper_bound_ns)
        );
        Ok(())
    } else {
        Err(format!(
            "benchmark threshold failed: {} mean upper bound {} > {}",
            threshold.name,
            format_ns(upper_bound_ns),
            format_ns(threshold.max_upper_bound_ns)
        ))
    }
}

fn read_estimates(name: &str) -> Result<Estimates, String> {
    let path = estimates_path(name);
    let json = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read {}: {error}. Run `just threshold-prf-bench` first.",
            path.display()
        )
    })?;
    serde_json::from_str(&json).map_err(|error| {
        format!(
            "failed to parse Criterion estimates at {}: {error}",
            path.display()
        )
    })
}

fn estimates_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("criterion")
        .join(CRITERION_GROUP)
        .join(name)
        .join("new")
        .join("estimates.json")
}

fn format_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.3} ms", ns / 1_000_000.0)
    } else if ns >= 1_000.0 {
        format!("{:.3} us", ns / 1_000.0)
    } else {
        format!("{ns:.3} ns")
    }
}
