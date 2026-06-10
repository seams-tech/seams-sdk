use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_hss::benchmark::{
    default_ddh_hidden_eval_allocation_probe_config,
    generate_ddh_hidden_eval_allocation_probe_report, DdhHiddenEvalAllocationMeasurement,
    DdhHiddenEvalAllocationRecorder,
};
use ed25519_hss::shared::ProtoResult;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_allocation(layout.size() as u64);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        record_deallocation(layout.size() as u64);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let next_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !next_ptr.is_null() {
            REALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            let old_size = layout.size() as u64;
            let next_size = new_size as u64;
            match next_size.cmp(&old_size) {
                std::cmp::Ordering::Greater => record_allocation(next_size - old_size),
                std::cmp::Ordering::Less => record_deallocation(old_size - next_size),
                std::cmp::Ordering::Equal => {}
            }
        }
        next_ptr
    }
}

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_ddh_hidden_eval_allocation_probe_config();
    config.fixture_name = args.fixture_name;
    config.warmup_iterations = args.warmup_iterations;
    config.sample_count = args.sample_count;

    let mut recorder = NativeAllocationRecorder;
    let report = generate_ddh_hidden_eval_allocation_probe_report(&config, &mut recorder)
        .expect("DDH hidden-eval allocation probe");
    let json =
        serde_json::to_string_pretty(&report).expect("serialize DDH hidden-eval allocation report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write DDH hidden-eval allocation report");
        eprintln!("wrote DDH hidden-eval allocation report to {path}");
    }

    if args.emit_json {
        println!("{json}");
    } else {
        for line in report.summary_lines() {
            println!("{line}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    warmup_iterations: u64,
    sample_count: usize,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            warmup_iterations: 1,
            sample_count: 5,
        };

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--json" => {
                    parsed.emit_json = true;
                    idx += 1;
                }
                "--output" => {
                    parsed.output_path = Some(read_next_value(&args, &mut idx, "--output")?);
                }
                "--fixture" => {
                    parsed.fixture_name = Some(read_next_value(&args, &mut idx, "--fixture")?);
                }
                "--warmup" => {
                    parsed.warmup_iterations =
                        parse_u64(&read_next_value(&args, &mut idx, "--warmup")?, "--warmup")?;
                }
                "--samples" => {
                    parsed.sample_count =
                        parse_usize(&read_next_value(&args, &mut idx, "--samples")?, "--samples")?;
                    if parsed.sample_count == 0 {
                        return Err(format!(
                            "--samples must be greater than 0\n\n{}",
                            Self::usage()
                        ));
                    }
                }
                "--help" | "-h" => {
                    return Err(Self::usage());
                }
                other => {
                    return Err(format!("unknown argument: {other}\n\n{}", Self::usage()));
                }
            }
        }

        Ok(parsed)
    }

    fn usage() -> String {
        [
            "Usage: benchmark_ddh_hidden_eval_alloc [options]",
            "",
            "Options:",
            "  --json                  Print the full JSON report",
            "  --output <path>         Write the JSON report to a file",
            "  --fixture <name>        Use a specific deterministic fixture",
            "  --warmup <n>            Hidden-eval warmup iterations",
            "  --samples <n>           Number of allocation samples",
        ]
        .join("\n")
    }
}

struct NativeAllocationRecorder;

impl DdhHiddenEvalAllocationRecorder for NativeAllocationRecorder {
    fn measure<F>(
        &mut self,
        _operation: &'static str,
        op: F,
    ) -> ProtoResult<DdhHiddenEvalAllocationMeasurement>
    where
        F: FnOnce() -> ProtoResult<()>,
    {
        let before = AllocSnapshot::capture();
        PEAK_LIVE_BYTES.store(before.live_bytes, Ordering::Relaxed);
        op()?;
        let after = AllocSnapshot::capture();
        let peak_live_bytes = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
        Ok(DdhHiddenEvalAllocationMeasurement {
            allocation_calls: after
                .allocation_calls
                .saturating_sub(before.allocation_calls),
            deallocation_calls: after
                .deallocation_calls
                .saturating_sub(before.deallocation_calls),
            reallocation_calls: after
                .reallocation_calls
                .saturating_sub(before.reallocation_calls),
            allocated_bytes: after.allocated_bytes.saturating_sub(before.allocated_bytes),
            deallocated_bytes: after
                .deallocated_bytes
                .saturating_sub(before.deallocated_bytes),
            live_bytes_before: before.live_bytes,
            live_bytes_after: after.live_bytes,
            live_bytes_delta: after.live_bytes as i128 - before.live_bytes as i128,
            peak_live_bytes_above_start: peak_live_bytes.saturating_sub(before.live_bytes),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllocSnapshot {
    allocation_calls: u64,
    deallocation_calls: u64,
    reallocation_calls: u64,
    allocated_bytes: u64,
    deallocated_bytes: u64,
    live_bytes: u64,
}

impl AllocSnapshot {
    fn capture() -> Self {
        Self {
            allocation_calls: ALLOCATION_CALLS.load(Ordering::Relaxed),
            deallocation_calls: DEALLOCATION_CALLS.load(Ordering::Relaxed),
            reallocation_calls: REALLOCATION_CALLS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            deallocated_bytes: DEALLOCATED_BYTES.load(Ordering::Relaxed),
            live_bytes: LIVE_BYTES.load(Ordering::Relaxed),
        }
    }
}

fn record_allocation(bytes: u64) {
    ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
    ALLOCATED_BYTES.fetch_add(bytes, Ordering::Relaxed);
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    update_peak_live_bytes(live);
}

fn record_deallocation(bytes: u64) {
    DEALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
    DEALLOCATED_BYTES.fetch_add(bytes, Ordering::Relaxed);
    let _ = LIVE_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
        Some(live.saturating_sub(bytes))
    });
}

fn update_peak_live_bytes(live: u64) {
    let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_LIVE_BYTES.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next_peak) => peak = next_peak,
        }
    }
}

fn read_next_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    if *idx >= args.len() {
        return Err(format!("missing value for {flag}\n\n{}", CliArgs::usage()));
    }
    let value = args[*idx].clone();
    *idx += 1;
    Ok(value)
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}
