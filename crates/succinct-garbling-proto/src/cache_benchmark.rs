use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact_stub::{
    build_candidate_artifact_stub, materialize_candidate_artifact_stub_bytes,
};
use crate::candidate::{build_fixed_hidden_core_candidate, CandidateBackendFamily};
use crate::error::{ProtoError, ProtoResult};
use crate::fixtures::deterministic_fixture_corpus;
use crate::prime_order_encoder::{
    build_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
};

pub const CACHE_BENCHMARK_REPORT_VERSION: &str = "cache_benchmark_report_v0";
pub const DEFAULT_CACHED_GC_BASELINE_BYTES: u64 = 1_200_000;
const DEFAULT_BANDWIDTHS_MBPS: [u64; 4] = [10, 25, 50, 100];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheBenchmarkConfig {
    pub warmup_samples: usize,
    pub timed_samples: usize,
    pub cached_gc_baseline_bytes: u64,
    pub bandwidths_mbps: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheBenchmarkReport {
    pub report_version: String,
    pub cached_gc_baseline_bytes: u64,
    pub bandwidths_mbps: Vec<u64>,
    pub targets: Vec<CacheBenchmarkTargetReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheBenchmarkTargetMaterialized {
    pub label: String,
    pub kind: String,
    pub backend_family: Option<CandidateBackendFamily>,
    pub bytes: Vec<u8>,
    pub bytes_sha256: [u8; 32],
    pub manifest_json: Option<String>,
    pub manifest_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheBenchmarkTargetReport {
    pub label: String,
    pub kind: String,
    pub backend_family: Option<CandidateBackendFamily>,
    pub bytes: u64,
    pub manifest_bytes: u64,
    pub size_ratio_vs_cached_gc: f64,
    pub estimated_download_ms: Vec<BandwidthEstimate>,
    pub cache_write_ns: CacheTimingStats,
    pub cache_read_ns: CacheTimingStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthEstimate {
    pub bandwidth_mbps: u64,
    pub estimated_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheTimingStats {
    pub min_ns: u128,
    pub median_ns: u128,
    pub mean_ns: u128,
    pub p95_ns: u128,
    pub max_ns: u128,
}

pub fn default_cache_benchmark_config() -> CacheBenchmarkConfig {
    CacheBenchmarkConfig {
        warmup_samples: 1,
        timed_samples: 8,
        cached_gc_baseline_bytes: DEFAULT_CACHED_GC_BASELINE_BYTES,
        bandwidths_mbps: DEFAULT_BANDWIDTHS_MBPS.to_vec(),
    }
}

pub fn generate_cache_benchmark_report(
    config: &CacheBenchmarkConfig,
) -> ProtoResult<CacheBenchmarkReport> {
    if config.timed_samples == 0 {
        return Err(ProtoError::InvalidInput(
            "timed_samples must be positive".to_string(),
        ));
    }

    let targets = materialize_cache_benchmark_targets(config)?
        .into_iter()
        .map(|target| {
            benchmark_target(
                &target.label,
                &target.kind,
                target.backend_family,
                &target.bytes,
                target.manifest_bytes,
                config,
            )
        })
        .collect::<ProtoResult<Vec<_>>>()?;

    Ok(CacheBenchmarkReport {
        report_version: CACHE_BENCHMARK_REPORT_VERSION.to_string(),
        cached_gc_baseline_bytes: config.cached_gc_baseline_bytes,
        bandwidths_mbps: config.bandwidths_mbps.clone(),
        targets,
    })
}

pub fn materialize_cache_benchmark_targets(
    config: &CacheBenchmarkConfig,
) -> ProtoResult<Vec<CacheBenchmarkTargetMaterialized>> {
    let fixture = deterministic_fixture_corpus()?
        .into_iter()
        .find(|fixture| fixture.name == "derived-alpha")
        .ok_or_else(|| ProtoError::Decode("missing derived-alpha fixture".to_string()))?;
    let candidate = build_fixed_hidden_core_candidate(&fixture.input.context)?;
    let stub_manifest = build_candidate_artifact_stub(&candidate)?;
    let stub_bytes = materialize_candidate_artifact_stub_bytes(&candidate)?;
    let stub_manifest_json = stub_manifest.to_json_pretty()?;
    let prime_order_manifest = build_prime_order_size_optimized_artifact(&candidate)?;
    let prime_order_bytes = materialize_prime_order_size_optimized_bytes(&candidate)?;
    let prime_order_manifest_json = prime_order_manifest.to_json_pretty()?;
    let cached_gc_bytes = materialize_cached_gc_baseline_bytes(config.cached_gc_baseline_bytes)?;

    Ok(vec![
        CacheBenchmarkTargetMaterialized {
            label: "cached_gc_baseline".to_string(),
            kind: "baseline".to_string(),
            backend_family: None,
            bytes_sha256: sha256_bytes(&cached_gc_bytes),
            bytes: cached_gc_bytes,
            manifest_json: None,
            manifest_bytes: 0,
        },
        CacheBenchmarkTargetMaterialized {
            label: "prime_order_stub_artifact".to_string(),
            kind: "candidate_stub".to_string(),
            backend_family: Some(candidate.backend.family),
            bytes_sha256: sha256_bytes(&stub_bytes),
            bytes: stub_bytes,
            manifest_json: Some(stub_manifest_json.clone()),
            manifest_bytes: stub_manifest_json.len() as u64,
        },
        CacheBenchmarkTargetMaterialized {
            label: "prime_order_structured_artifact".to_string(),
            kind: "candidate_structured".to_string(),
            backend_family: Some(candidate.backend.family),
            bytes_sha256: sha256_bytes(&prime_order_bytes),
            bytes: prime_order_bytes,
            manifest_json: Some(prime_order_manifest_json.clone()),
            manifest_bytes: prime_order_manifest_json.len() as u64,
        },
    ])
}

impl CacheBenchmarkReport {
    pub fn to_json_pretty(&self) -> ProtoResult<String> {
        serde_json::to_string_pretty(self).map_err(|err| {
            ProtoError::Decode(format!("failed to serialize cache benchmark report: {err}"))
        })
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "cache benchmark: cached_gc_baseline={}B bandwidths={:?}",
            self.cached_gc_baseline_bytes, self.bandwidths_mbps
        ));

        for target in &self.targets {
            lines.push(format!(
                "{}: bytes={} manifest={}B ratio_vs_cached_gc={:.3}",
                target.label, target.bytes, target.manifest_bytes, target.size_ratio_vs_cached_gc
            ));
            lines.push(format!(
                "  write_ns mean={} median={} p95={}",
                target.cache_write_ns.mean_ns,
                target.cache_write_ns.median_ns,
                target.cache_write_ns.p95_ns,
            ));
            lines.push(format!(
                "  read_ns mean={} median={} p95={}",
                target.cache_read_ns.mean_ns,
                target.cache_read_ns.median_ns,
                target.cache_read_ns.p95_ns,
            ));
            for estimate in &target.estimated_download_ms {
                lines.push(format!(
                    "  download@{}Mbps={}ms",
                    estimate.bandwidth_mbps, estimate.estimated_ms
                ));
            }
        }

        lines
    }
}

fn benchmark_target(
    label: &str,
    kind: &str,
    backend_family: Option<CandidateBackendFamily>,
    bytes: &[u8],
    manifest_bytes: u64,
    config: &CacheBenchmarkConfig,
) -> ProtoResult<CacheBenchmarkTargetReport> {
    let temp_dir = make_temp_dir(label)?;
    let artifact_path = temp_dir.join("artifact.bin");

    for _ in 0..config.warmup_samples {
        fs::write(&artifact_path, bytes)
            .map_err(|err| ProtoError::Decode(format!("warmup write failed: {err}")))?;
        let _ = fs::read(&artifact_path)
            .map_err(|err| ProtoError::Decode(format!("warmup read failed: {err}")))?;
    }

    let mut write_samples = Vec::with_capacity(config.timed_samples);
    let mut read_samples = Vec::with_capacity(config.timed_samples);

    for _ in 0..config.timed_samples {
        let start = Instant::now();
        fs::write(&artifact_path, bytes)
            .map_err(|err| ProtoError::Decode(format!("timed write failed: {err}")))?;
        write_samples.push(start.elapsed().as_nanos());

        let start = Instant::now();
        let _ = fs::read(&artifact_path)
            .map_err(|err| ProtoError::Decode(format!("timed read failed: {err}")))?;
        read_samples.push(start.elapsed().as_nanos());
    }

    let _ = fs::remove_dir_all(&temp_dir);

    let bytes_len = bytes.len() as u64;

    Ok(CacheBenchmarkTargetReport {
        label: label.to_string(),
        kind: kind.to_string(),
        backend_family,
        bytes: bytes_len,
        manifest_bytes,
        size_ratio_vs_cached_gc: bytes_len as f64 / config.cached_gc_baseline_bytes as f64,
        estimated_download_ms: config
            .bandwidths_mbps
            .iter()
            .copied()
            .map(|bandwidth_mbps| BandwidthEstimate {
                bandwidth_mbps,
                estimated_ms: estimate_download_ms(bytes_len, bandwidth_mbps),
            })
            .collect(),
        cache_write_ns: stats_from_samples(write_samples),
        cache_read_ns: stats_from_samples(read_samples),
    })
}

fn materialize_cached_gc_baseline_bytes(total_bytes: u64) -> ProtoResult<Vec<u8>> {
    let total_bytes = usize::try_from(total_bytes).map_err(|_| {
        ProtoError::InvalidInput("cached GC bytes do not fit into usize".to_string())
    })?;
    let mut out = Vec::with_capacity(total_bytes);
    let mut counter = 0u64;

    while out.len() < total_bytes {
        let block = sha256_concat(&[
            b"succinct-garbling-proto/cached-gc-baseline/v0",
            &counter.to_be_bytes(),
        ]);
        let remaining = total_bytes - out.len();
        let take = remaining.min(block.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }

    Ok(out)
}

fn make_temp_dir(label: &str) -> ProtoResult<PathBuf> {
    let unique = format!(
        "sg-cache-benchmark-{}-{}",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| ProtoError::Decode(format!("system time error: {err}")))?
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    fs::create_dir_all(&path)
        .map_err(|err| ProtoError::Decode(format!("failed to create temp dir: {err}")))?;
    Ok(path)
}

fn estimate_download_ms(bytes: u64, bandwidth_mbps: u64) -> u64 {
    let bits = bytes.saturating_mul(8);
    let bits_per_second = bandwidth_mbps.saturating_mul(1_000_000);
    ((bits as f64 / bits_per_second as f64) * 1000.0).ceil() as u64
}

fn stats_from_samples(mut samples: Vec<u128>) -> CacheTimingStats {
    samples.sort_unstable();
    let min_ns = samples[0];
    let max_ns = samples[samples.len() - 1];
    let median_ns = percentile(&samples, 0.5);
    let p95_ns = percentile(&samples, 0.95);
    let mean_ns = samples.iter().sum::<u128>() / samples.len() as u128;

    CacheTimingStats {
        min_ns,
        median_ns,
        mean_ns,
        p95_ns,
        max_ns,
    }
}

fn percentile(sorted: &[u128], quantile: f64) -> u128 {
    let idx = ((sorted.len() - 1) as f64 * quantile).round() as usize;
    sorted[idx]
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
