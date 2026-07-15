#![forbid(unsafe_code)]

use ed25519_yao::phase5_wasm_benchmark::{
    WasmBenchmarkError, WasmBenchmarkFamily, WasmBenchmarkReport, WasmBenchmarkSession,
    WasmChunkProfile,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Returns the current WebAssembly linear-memory size in bytes.
#[wasm_bindgen]
pub fn wasm_linear_memory_bytes() -> u32 {
    let memory: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
    let buffer: js_sys::ArrayBuffer = memory.buffer().unchecked_into();
    buffer.byte_length()
}

enum ExportedSessionState {
    Active(Box<WasmBenchmarkSession>),
    Consumed,
}

/// Host-driven, frame-at-a-time Phase 5 benchmark session.
#[wasm_bindgen]
pub struct Phase5StreamBenchmark {
    state: ExportedSessionState,
}

#[wasm_bindgen]
impl Phase5StreamBenchmark {
    /// Creates a fresh fixed-family, fixed-profile benchmark session.
    #[wasm_bindgen(constructor)]
    pub fn new(family: &str, profile: &str) -> Result<Phase5StreamBenchmark, JsValue> {
        let family = parse_family(family)?;
        let profile = parse_profile(profile)?;
        let session = WasmBenchmarkSession::new(family, profile).map_err(benchmark_error)?;
        Ok(Self {
            state: ExportedSessionState::Active(Box::new(session)),
        })
    }

    /// Returns the exact number of table frames the host must relay.
    pub fn expected_frame_count(&self) -> Result<u32, JsValue> {
        self.session()
            .map(WasmBenchmarkSession::expected_frame_count)
    }

    /// Returns the exact payload-plus-header body length.
    pub fn expected_body_bytes(&self) -> Result<u64, JsValue> {
        self.session()
            .map(WasmBenchmarkSession::expected_body_bytes)
    }

    /// Copies the 248-byte opening manifest into one host-owned message.
    pub fn take_opening_manifest(&mut self) -> Result<Vec<u8>, JsValue> {
        self.session_mut()?
            .take_opening_manifest()
            .map(|manifest| manifest.into_bytes())
            .map_err(benchmark_error)
    }

    /// Returns the host-delivered opening manifest to the bounded parser.
    pub fn accept_opening_manifest(&mut self, mut encoded: Vec<u8>) -> Result<(), JsValue> {
        let result = self
            .session_mut()?
            .accept_opening_manifest(&encoded)
            .map_err(benchmark_error);
        encoded.fill(0);
        result
    }

    /// Produces one frame and pauses until `accept_table_frame` returns it.
    pub fn next_table_frame(&mut self) -> Result<Vec<u8>, JsValue> {
        self.session_mut()?
            .next_table_frame()
            .map(|frame| frame.into_bytes())
            .map_err(benchmark_error)
    }

    /// Returns one host-delivered frame to the parser and incremental evaluator.
    pub fn accept_table_frame(&mut self, mut encoded: Vec<u8>) -> Result<(), JsValue> {
        let result = self
            .session_mut()?
            .accept_table_frame(&encoded)
            .map_err(benchmark_error);
        encoded.fill(0);
        result
    }

    /// Confirms that the host closed A's outbound body.
    pub fn confirm_outbound_body_closed(&mut self) -> Result<(), JsValue> {
        self.session_mut()?
            .confirm_outbound_body_closed()
            .map_err(benchmark_error)
    }

    /// Confirms that B's host observed exact body EOF.
    pub fn confirm_inbound_exact_eof(&mut self) -> Result<(), JsValue> {
        self.session_mut()?
            .confirm_inbound_exact_eof()
            .map_err(benchmark_error)
    }

    /// Consumes the terminal session and returns scalar-only evidence.
    pub fn finish(&mut self) -> Result<Phase5StreamReport, JsValue> {
        let state = core::mem::replace(&mut self.state, ExportedSessionState::Consumed);
        let ExportedSessionState::Active(session) = state else {
            return Err(consumed_error());
        };
        (*session)
            .finish()
            .map(Phase5StreamReport::new)
            .map_err(benchmark_error)
    }
}

impl Phase5StreamBenchmark {
    fn session(&self) -> Result<&WasmBenchmarkSession, JsValue> {
        match &self.state {
            ExportedSessionState::Active(session) => Ok(session.as_ref()),
            ExportedSessionState::Consumed => Err(consumed_error()),
        }
    }

    fn session_mut(&mut self) -> Result<&mut WasmBenchmarkSession, JsValue> {
        match &mut self.state {
            ExportedSessionState::Active(session) => Ok(session.as_mut()),
            ExportedSessionState::Consumed => Err(consumed_error()),
        }
    }
}

/// Scalar-only Phase 5 stream, memory, allocation, and copy evidence.
#[wasm_bindgen]
pub struct Phase5StreamReport {
    inner: WasmBenchmarkReport,
}

#[wasm_bindgen]
impl Phase5StreamReport {
    /// Returns `activation` or `export`.
    pub fn family(&self) -> String {
        self.inner.family().as_str().to_owned()
    }

    /// Returns `64kib`, `128kib`, or `256kib`.
    pub fn profile(&self) -> String {
        self.inner.profile().as_str().to_owned()
    }

    /// Returns exact table payload bytes.
    pub fn table_payload_bytes(&self) -> usize {
        self.inner.table_payload_bytes()
    }

    /// Returns exact table payload plus frame-header bytes.
    pub fn body_bytes(&self) -> u64 {
        self.inner.body_bytes()
    }

    /// Returns the exact frame count.
    pub fn frame_count(&self) -> u32 {
        self.inner.frame_count()
    }

    /// Returns Deriver A's peak live table buffer.
    pub fn deriver_a_peak_table_buffer_bytes(&self) -> usize {
        self.inner.deriver_a_peak_table_buffer_bytes()
    }

    /// Returns Deriver B's peak borrowed frame payload.
    pub fn deriver_b_peak_table_buffer_bytes(&self) -> usize {
        self.inner.deriver_b_peak_table_buffer_bytes()
    }

    /// Returns Deriver A's wire-arena allocation.
    pub fn deriver_a_peak_arena_bytes(&self) -> usize {
        self.inner.deriver_a_peak_arena_bytes()
    }

    /// Returns Deriver B's wire-arena allocation.
    pub fn deriver_b_peak_arena_bytes(&self) -> usize {
        self.inner.deriver_b_peak_arena_bytes()
    }

    /// Returns transport-neutral runtime host-copy bytes.
    pub fn runtime_host_boundary_copy_bytes(&self) -> usize {
        self.inner.runtime_host_boundary_copy_bytes()
    }

    /// Returns payload bytes copied from A's reusable chunk into Rust wire frames.
    pub fn runtime_chunk_to_wire_copy_bytes(&self) -> u64 {
        self.inner.runtime_chunk_to_wire_copy_bytes()
    }

    /// Returns writes into A's reusable chunk buffer.
    pub fn table_buffer_write_bytes(&self) -> usize {
        self.inner.table_buffer_write_bytes()
    }

    /// Returns the exact number of decoded AND-table records.
    pub fn and_records_decoded(&self) -> usize {
        self.inner.and_records_decoded()
    }

    /// Returns manifest bytes copied from WASM to the host.
    pub fn wasm_to_host_manifest_copy_bytes(&self) -> u64 {
        self.inner.boundary_metrics().outbound_manifest_copy_bytes()
    }

    /// Returns manifest bytes copied from the host into WASM.
    pub fn host_to_wasm_manifest_copy_bytes(&self) -> u64 {
        self.inner.boundary_metrics().inbound_manifest_copy_bytes()
    }

    /// Returns framed bytes copied from WASM to the host.
    pub fn wasm_to_host_frame_copy_bytes(&self) -> u64 {
        self.inner.boundary_metrics().outbound_frame_copy_bytes()
    }

    /// Returns framed bytes copied from the host into WASM.
    pub fn host_to_wasm_frame_copy_bytes(&self) -> u64 {
        self.inner.boundary_metrics().inbound_frame_copy_bytes()
    }

    /// Returns the number of Rust-owned frame allocations.
    pub fn rust_frame_allocations(&self) -> u32 {
        self.inner.boundary_metrics().rust_frame_allocations()
    }

    /// Returns cumulative Rust-owned frame allocation bytes.
    pub fn rust_frame_allocation_bytes(&self) -> u64 {
        self.inner.boundary_metrics().rust_frame_allocation_bytes()
    }

    /// Returns the largest live Rust-owned frame allocation.
    pub fn peak_rust_frame_allocation_bytes(&self) -> usize {
        self.inner
            .boundary_metrics()
            .peak_rust_frame_allocation_bytes()
    }
}

impl Phase5StreamReport {
    fn new(inner: WasmBenchmarkReport) -> Self {
        Self { inner }
    }
}

/// Returns the isolated incremental adapter schema identifier.
#[wasm_bindgen]
pub fn phase5_stream_adapter_schema() -> String {
    "ed25519_yao_phase5_wasm_stream_v1".to_owned()
}

fn parse_profile(value: &str) -> Result<WasmChunkProfile, JsValue> {
    match value {
        "64kib" => Ok(WasmChunkProfile::KiB64),
        "128kib" => Ok(WasmChunkProfile::KiB128),
        "256kib" => Ok(WasmChunkProfile::KiB256),
        _ => Err(JsValue::from_str("unsupported Phase 5 chunk profile")),
    }
}

fn parse_family(value: &str) -> Result<WasmBenchmarkFamily, JsValue> {
    match value {
        "activation" => Ok(WasmBenchmarkFamily::Activation),
        "export" => Ok(WasmBenchmarkFamily::Export),
        _ => Err(JsValue::from_str("unsupported Phase 5 circuit family")),
    }
}

fn benchmark_error(_: WasmBenchmarkError) -> JsValue {
    JsValue::from_str("isolated Phase 5 WASM stream benchmark failed")
}

fn consumed_error() -> JsValue {
    JsValue::from_str("Phase 5 WASM stream benchmark already consumed")
}
