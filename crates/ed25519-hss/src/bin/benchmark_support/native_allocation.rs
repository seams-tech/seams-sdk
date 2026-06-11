use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_hss::benchmark::{DdhHiddenEvalAllocationMeasurement, DdhHiddenEvalAllocationRecorder};
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

pub struct NativeAllocationRecorder;

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
