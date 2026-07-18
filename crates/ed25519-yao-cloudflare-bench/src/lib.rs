#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Benchmark-only Cloudflare adapter for the fixed activation/128 KiB Yao roles.

#[cfg(any(
    all(feature = "deriver-a", feature = "deriver-a-cross-account"),
    all(feature = "deriver-a", feature = "deriver-a-same-account-websocket"),
    all(feature = "deriver-a", feature = "deriver-b"),
    all(feature = "deriver-a", feature = "deriver-b-cross-account"),
    all(feature = "deriver-a", feature = "deriver-b-same-account-websocket"),
    all(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ),
    all(feature = "deriver-a-cross-account", feature = "deriver-b"),
    all(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account"
    ),
    all(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-same-account-websocket"
    ),
    all(feature = "deriver-a-same-account-websocket", feature = "deriver-b"),
    all(
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-cross-account"
    ),
    all(
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket"
    ),
    all(feature = "deriver-b", feature = "deriver-b-cross-account"),
    all(feature = "deriver-b", feature = "deriver-b-same-account-websocket"),
    all(
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    )
))]
compile_error!("select exactly one Cloudflare role feature");

#[cfg(any(
    all(
        feature = "fault-fragmentation",
        any(
            feature = "fault-request-disconnect-after-base-choices",
            feature = "fault-response-disconnect-after-offer",
            feature = "fault-trailing-after-terminal",
            feature = "fault-short-timeout",
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-request-disconnect-after-base-choices",
        any(
            feature = "fault-response-disconnect-after-offer",
            feature = "fault-trailing-after-terminal",
            feature = "fault-short-timeout",
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-response-disconnect-after-offer",
        any(
            feature = "fault-trailing-after-terminal",
            feature = "fault-short-timeout",
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-trailing-after-terminal",
        any(
            feature = "fault-short-timeout",
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-short-timeout",
        any(
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-stall-after-offer",
        any(
            feature = "fault-wrong-role-offer-tag",
            feature = "fault-session-mismatch"
        )
    ),
    all(
        feature = "fault-wrong-role-offer-tag",
        feature = "fault-session-mismatch"
    )
))]
compile_error!("select at most one compile-time fault feature");

#[cfg(all(
    feature = "fault-fragmentation",
    not(any(feature = "deriver-a", feature = "deriver-b"))
))]
compile_error!("fault-fragmentation requires the same-account deriver-a or deriver-b role");

#[cfg(all(
    feature = "fault-request-disconnect-after-base-choices",
    not(feature = "deriver-a")
))]
compile_error!("fault-request-disconnect-after-base-choices requires same-account deriver-a");

#[cfg(all(
    feature = "fault-response-disconnect-after-offer",
    not(feature = "deriver-b")
))]
compile_error!("fault-response-disconnect-after-offer requires same-account deriver-b");

#[cfg(all(feature = "fault-trailing-after-terminal", not(feature = "deriver-b")))]
compile_error!("fault-trailing-after-terminal requires same-account deriver-b");

#[cfg(all(feature = "fault-short-timeout", not(feature = "deriver-a")))]
compile_error!("fault-short-timeout requires same-account deriver-a");

#[cfg(all(feature = "fault-stall-after-offer", not(feature = "deriver-b")))]
compile_error!("fault-stall-after-offer requires same-account deriver-b");

#[cfg(all(feature = "fault-wrong-role-offer-tag", not(feature = "deriver-b")))]
compile_error!("fault-wrong-role-offer-tag requires same-account deriver-b");

#[cfg(all(feature = "fault-session-mismatch", not(feature = "deriver-b")))]
compile_error!("fault-session-mismatch requires same-account deriver-b");

#[cfg(all(
    target_arch = "wasm32",
    not(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))
))]
compile_error!("a Worker build requires exactly one Deriver A or Deriver B transport feature");

#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket",
    feature = "deriver-b",
    feature = "deriver-b-cross-account",
    feature = "deriver-b-same-account-websocket",
    test
))]
mod adapter {
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    use std::cell::RefCell;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    use std::collections::VecDeque;
    use std::fmt;
    use std::pin::Pin;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    use std::rc::Rc;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    use ed25519_yao::phase9_role_benchmark::Activation128KiBDeriverA;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    use ed25519_yao::phase9_role_benchmark::ActivationDeriverACompletion;
    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    use ed25519_yao::phase9_role_benchmark::{
        Activation128KiBDeriverB, ActivationDeriverBCompletion,
    };
    use ed25519_yao::phase9_role_benchmark::{
        BenchmarkRoleError, DirectionalEofEvidence, DirectionalWireDecoder, DirectionalWireEncoder,
        RelayEvent, RelayInstruction, RelayStep, WireByteLedger, WireDirection, WireMessage,
        WireMessageKind,
    };
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    use futures_channel::mpsc;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    use futures_channel::oneshot;
    use futures_core::Stream;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    use futures_util::future::{select, Either as FutureEither};
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    use futures_util::SinkExt;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    use futures_util::StreamExt;
    use http_body::Frame;
    #[cfg(feature = "deriver-a")]
    use http_body_util::StreamBody;
    #[cfg(feature = "deriver-a-same-account-rpc")]
    use worker::js_sys::futures::{spawn_local, JsFuture};
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    use worker::wasm_bindgen::JsCast;
    #[cfg(feature = "deriver-a-same-account-rpc")]
    use worker::wasm_bindgen::{prelude::wasm_bindgen, JsValue};
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    use worker::Body;
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    use worker::Env;
    use zeroize::Zeroizing;

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) const BENCHMARK_PATH: &str = "/benchmark/activation";
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(super) const SESSION_HEADER: &str = "x-ed25519-yao-session";
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) const DEPLOYMENT_ID_HEADER: &str = "x-ed25519-yao-deployment-id";
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    const BENCHMARK_DEPLOYMENT_ID: &str = "BENCHMARK_DEPLOYMENT_ID";
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) const DERIVER_A_COLO_HEADER: &str = "x-ed25519-yao-a-colo";
    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) const DERIVER_B_COLO_HEADER: &str = "x-ed25519-yao-b-colo";
    #[cfg(any(feature = "deriver-a", feature = "deriver-a-same-account-websocket"))]
    const DERIVER_B_BINDING: &str = "DERIVER_B";
    #[cfg(any(feature = "deriver-a", feature = "deriver-a-same-account-websocket"))]
    const DERIVER_B_URL: &str = "https://ed25519-yao-b.internal/benchmark/activation";
    #[cfg(feature = "deriver-a-cross-account")]
    const DERIVER_B_WEBSOCKET_ENDPOINT: &str = "DERIVER_B_WEBSOCKET_ENDPOINT";

    #[cfg(feature = "deriver-a-same-account-rpc")]
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(extends = worker::js_sys::Object)]
        #[derive(Clone)]
        type DeriverBRpc;

        #[wasm_bindgen(method, catch, js_name = runCeremony)]
        fn run_ceremony(
            this: &DeriverBRpc,
            a_to_b: worker::web_sys::ReadableStream,
            b_to_a: worker::web_sys::WritableStream,
            deployment_id: &str,
            session: &str,
            deriver_a_colo: JsValue,
        ) -> Result<worker::js_sys::Promise, JsValue>;
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    #[wasm_bindgen(module = "/rpc/identity-byte-pipe.mjs")]
    extern "C" {
        #[derive(Clone)]
        type RpcIdentityBytePipe;

        #[wasm_bindgen(js_name = createRpcIdentityBytePipe)]
        fn create_rpc_identity_byte_pipe() -> RpcIdentityBytePipe;

        #[wasm_bindgen(method, getter)]
        fn readable(this: &RpcIdentityBytePipe) -> worker::web_sys::ReadableStream;

        #[wasm_bindgen(method, getter)]
        fn writable(this: &RpcIdentityBytePipe) -> worker::web_sys::WritableStream;

        #[wasm_bindgen(method, catch)]
        fn write(
            this: &RpcIdentityBytePipe,
            chunk: &[u8],
        ) -> Result<worker::js_sys::Promise, JsValue>;

        #[wasm_bindgen(method, catch)]
        fn close(this: &RpcIdentityBytePipe) -> Result<worker::js_sys::Promise, JsValue>;

        #[wasm_bindgen(method, catch)]
        fn abort(
            this: &RpcIdentityBytePipe,
            reason: &str,
        ) -> Result<worker::js_sys::Promise, JsValue>;
    }
    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    const WEBSOCKET_PROTOCOL_PREFIX: &str = "yaos-ab-v1";
    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    const WEBSOCKET_DIRECTION_EOF: &[u8] = b"YAOEOF01A";
    #[cfg(all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")))]
    pub(super) const A_TOPOLOGY_LABEL: &str = "same-account-service-binding";
    #[cfg(feature = "deriver-a-same-account-rpc")]
    pub(super) const A_TOPOLOGY_LABEL: &str = "same-account-service-binding-rpc-streams";
    #[cfg(feature = "deriver-a-cross-account")]
    pub(super) const A_TOPOLOGY_LABEL: &str = "cross-account-websocket";
    #[cfg(feature = "deriver-a-same-account-websocket")]
    pub(super) const A_TOPOLOGY_LABEL: &str = "same-account-service-binding-websocket";
    #[cfg(all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")))]
    pub(super) const TABLE_TIMING_BOUNDARY: &str = "outbound-stream-backpressure-acceptance";
    #[cfg(feature = "deriver-a-same-account-rpc")]
    pub(super) const TABLE_TIMING_BOUNDARY: &str = "rpc-writable-stream-backpressure-acceptance";
    #[cfg(feature = "deriver-a-cross-account")]
    pub(super) const TABLE_TIMING_BOUNDARY: &str = "websocket-send-queue-acceptance";
    #[cfg(feature = "deriver-a-same-account-websocket")]
    pub(super) const TABLE_TIMING_BOUNDARY: &str = "websocket-send-queue-acceptance";
    #[cfg(all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")))]
    pub(super) const BODY_BYTE_TIMING_BOUNDARY: &str = "raw-stream-chunk-emission-and-receipt";
    #[cfg(feature = "deriver-a-same-account-rpc")]
    pub(super) const BODY_BYTE_TIMING_BOUNDARY: &str =
        "rpc-transferred-stream-chunk-emission-and-receipt";
    #[cfg(feature = "deriver-a-cross-account")]
    pub(super) const BODY_BYTE_TIMING_BOUNDARY: &str = "websocket-binary-message-send-and-receipt";
    #[cfg(feature = "deriver-a-same-account-websocket")]
    pub(super) const BODY_BYTE_TIMING_BOUNDARY: &str = "websocket-binary-message-send-and-receipt";
    #[cfg(all(feature = "deriver-b", not(feature = "deriver-b-same-account-rpc")))]
    pub(super) const B_TOPOLOGY_LABEL: &str = "same-account-service-binding";
    #[cfg(feature = "deriver-b-same-account-rpc")]
    pub(super) const B_TOPOLOGY_LABEL: &str = "same-account-service-binding-rpc-streams";
    #[cfg(feature = "deriver-b-cross-account")]
    pub(super) const B_TOPOLOGY_LABEL: &str = "cross-account-websocket";
    #[cfg(feature = "deriver-b-same-account-websocket")]
    pub(super) const B_TOPOLOGY_LABEL: &str = "same-account-service-binding-websocket";
    #[cfg(all(
        test,
        not(any(
            feature = "deriver-b",
            feature = "deriver-b-cross-account",
            feature = "deriver-b-same-account-websocket"
        ))
    ))]
    const B_TOPOLOGY_LABEL: &str = "test-only";
    pub(super) const WORKERS_RS_VERSION: &str = "0.8.5";
    pub(super) const ADAPTER_SECRET_INGRESS_RUST_COPY_PASSES: u64 = 1;
    pub(super) const WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES: u64 = 1;
    pub(super) const MAX_QUEUED_OUTGOING_ENVELOPES: usize = 1;
    pub(super) const PRODUCTION_ELIGIBLE: bool = false;
    pub(super) const INCOMING_SECRET_BUFFER_DISPOSAL: &str =
        "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled";

    pub(super) fn add_nonpromotion_fields(report: &mut serde_json::Value) {
        let object = report
            .as_object_mut()
            .expect("benchmark reports are constructed as JSON objects");
        object.insert(
            "production_eligible".to_owned(),
            serde_json::Value::Bool(PRODUCTION_ELIGIBLE),
        );
        object.insert(
            "incoming_secret_buffer_disposal".to_owned(),
            serde_json::Value::String(INCOMING_SECRET_BUFFER_DISPOSAL.to_owned()),
        );
    }

    pub(super) fn add_deployment_id_field(
        report: &mut serde_json::Value,
        deployment_id: &DeploymentId,
    ) {
        let object = report
            .as_object_mut()
            .expect("benchmark reports are constructed as JSON objects");
        object.insert(
            "deployment_id".to_owned(),
            serde_json::Value::String(deployment_id.as_str().to_owned()),
        );
    }

    fn insert_wire_number(
        object: &mut serde_json::Map<String, serde_json::Value>,
        field: &'static str,
        value: u64,
    ) {
        object.insert(field.to_owned(), serde_json::Value::from(value));
    }

    pub(super) fn add_wire_fields(report: &mut serde_json::Value, wire: WireByteLedger) {
        let object = report
            .as_object_mut()
            .expect("benchmark reports are constructed as JSON objects");
        insert_wire_number(
            object,
            "table_framing_payload_bytes",
            wire.table_framing_payload_bytes(),
        );
        insert_wire_number(object, "table_protocol_bytes", wire.table_protocol_bytes());
        insert_wire_number(object, "ot_payload_bytes", wire.ot_payload_bytes());
        insert_wire_number(
            object,
            "other_control_payload_bytes",
            wire.other_control_payload_bytes(),
        );
        insert_wire_number(
            object,
            "envelope_header_bytes",
            wire.envelope_header_bytes(),
        );
        insert_wire_number(
            object,
            "table_transport_bytes",
            wire.table_transport_bytes(),
        );
        insert_wire_number(
            object,
            "control_transport_bytes",
            wire.control_transport_bytes(),
        );
        insert_wire_number(
            object,
            "deriver_a_to_b_transport_bytes",
            wire.deriver_a_to_b_transport_bytes(),
        );
        insert_wire_number(
            object,
            "deriver_b_to_a_transport_bytes",
            wire.deriver_b_to_a_transport_bytes(),
        );
        insert_wire_number(
            object,
            "total_ab_transport_bytes",
            wire.total_ab_transport_bytes(),
        );
        insert_wire_number(
            object,
            "transport_message_count",
            u64::from(wire.transport_message_count()),
        );
        insert_wire_number(
            object,
            "ot_message_count",
            u64::from(wire.ot_message_count()),
        );
        insert_wire_number(
            object,
            "ot_sequential_round_count",
            u64::from(wire.ot_sequential_round_count()),
        );
    }

    pub(super) fn add_secret_ingress_copy_fields(
        report: &mut serde_json::Value,
        metrics: AdapterIoMetrics,
    ) {
        let object = report
            .as_object_mut()
            .expect("benchmark reports are constructed as JSON objects");
        insert_wire_number(
            object,
            "adapter_secret_ingress_rust_copy_passes",
            ADAPTER_SECRET_INGRESS_RUST_COPY_PASSES,
        );
        insert_wire_number(
            object,
            "adapter_secret_ingress_rust_copy_bytes",
            metrics.adapter_secret_ingress_rust_copy_bytes(),
        );
        insert_wire_number(
            object,
            "adapter_secret_ingress_js_overwrite_bytes",
            metrics.adapter_secret_ingress_js_overwrite_bytes(),
        );
    }
    #[cfg(all(
        any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ),
        feature = "fault-short-timeout"
    ))]
    const CEREMONY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
    #[cfg(all(
        any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ),
        not(feature = "fault-short-timeout")
    ))]
    const CEREMONY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum AdapterError {
        Role,
        Envelope,
        InboundBody,
        OutboundBody,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        OutboundClosed,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        OutboundEof,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket",
            test
        ))]
        PeerStatus,
        ProtocolState,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        Randomness,
        #[cfg(any(feature = "deriver-a-cross-account", test))]
        CrossAccountEndpoint,
        PlacementEvidence,
        DeploymentIdentity,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket",
            test
        ))]
        TimingEvidence,
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-b-cross-account",
            feature = "deriver-a-same-account-websocket",
            feature = "deriver-b-same-account-websocket"
        ))]
        WebSocket,
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-b-cross-account",
            feature = "deriver-a-same-account-websocket",
            feature = "deriver-b-same-account-websocket"
        ))]
        WebSocketConnect,
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-b-cross-account",
            feature = "deriver-a-same-account-websocket",
            feature = "deriver-b-same-account-websocket",
            test
        ))]
        WebSocketProtocol,
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-b-cross-account",
            feature = "deriver-a-same-account-websocket",
            feature = "deriver-b-same-account-websocket"
        ))]
        WebSocketEvent,
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-b-cross-account",
            feature = "deriver-a-same-account-websocket",
            feature = "deriver-b-same-account-websocket"
        ))]
        WebSocketSend,
        #[cfg(any(feature = "deriver-a", feature = "deriver-a-same-account-websocket"))]
        ServiceBinding,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        Timeout,
        MeasurementOverflow,
        WireAccounting,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        PublicRequestBodyNonEmpty,
        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        PublicRequestBodyUnreadable,
        #[cfg(feature = "fault-request-disconnect-after-base-choices")]
        InjectedRequestDisconnect,
        #[cfg(feature = "fault-response-disconnect-after-offer")]
        InjectedResponseDisconnect,
    }

    impl AdapterError {
        pub(super) const fn code(self) -> &'static str {
            match self {
                Self::Role => "YAOS_AB_ROLE",
                Self::Envelope => "YAOS_AB_ENVELOPE",
                Self::InboundBody => "YAOS_AB_INBOUND_BODY",
                Self::OutboundBody => "YAOS_AB_OUTBOUND_BODY",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::OutboundClosed => "YAOS_AB_OUTBOUND_CLOSED",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::OutboundEof => "YAOS_AB_OUTBOUND_EOF",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    test
                ))]
                Self::PeerStatus => "YAOS_AB_PEER_STATUS",
                Self::ProtocolState => "YAOS_AB_PROTOCOL_STATE",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::Randomness => "YAOS_AB_RANDOMNESS",
                #[cfg(any(feature = "deriver-a-cross-account", test))]
                Self::CrossAccountEndpoint => "YAOS_AB_CROSS_ACCOUNT_ENDPOINT",
                Self::PlacementEvidence => "YAOS_AB_PLACEMENT_EVIDENCE",
                Self::DeploymentIdentity => "YAOS_AB_DEPLOYMENT_IDENTITY",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    test
                ))]
                Self::TimingEvidence => "YAOS_AB_TIMING_EVIDENCE",
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-b-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    feature = "deriver-b-same-account-websocket"
                ))]
                Self::WebSocket => "YAOS_AB_WEBSOCKET",
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-b-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    feature = "deriver-b-same-account-websocket"
                ))]
                Self::WebSocketConnect => "YAOS_AB_WEBSOCKET_CONNECT",
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-b-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    feature = "deriver-b-same-account-websocket",
                    test
                ))]
                Self::WebSocketProtocol => "YAOS_AB_WEBSOCKET_PROTOCOL",
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-b-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    feature = "deriver-b-same-account-websocket"
                ))]
                Self::WebSocketEvent => "YAOS_AB_WEBSOCKET_EVENT",
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-b-cross-account",
                    feature = "deriver-a-same-account-websocket",
                    feature = "deriver-b-same-account-websocket"
                ))]
                Self::WebSocketSend => "YAOS_AB_WEBSOCKET_SEND",
                #[cfg(any(feature = "deriver-a", feature = "deriver-a-same-account-websocket"))]
                Self::ServiceBinding => "YAOS_AB_SERVICE_BINDING",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::Timeout => "YAOS_AB_TIMEOUT",
                Self::MeasurementOverflow => "YAOS_AB_MEASUREMENT_OVERFLOW",
                Self::WireAccounting => "YAOS_AB_WIRE_ACCOUNTING",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::PublicRequestBodyNonEmpty => "YAOS_AB_PUBLIC_BODY_NONEMPTY",
                #[cfg(any(
                    feature = "deriver-a",
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                Self::PublicRequestBodyUnreadable => "YAOS_AB_PUBLIC_BODY_UNREADABLE",
                #[cfg(feature = "fault-request-disconnect-after-base-choices")]
                Self::InjectedRequestDisconnect => "YAOS_AB_INJECTED_REQUEST_DISCONNECT",
                #[cfg(feature = "fault-response-disconnect-after-offer")]
                Self::InjectedResponseDisconnect => "YAOS_AB_INJECTED_RESPONSE_DISCONNECT",
            }
        }
    }

    impl fmt::Display for AdapterError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.code())
        }
    }

    impl std::error::Error for AdapterError {}

    impl From<BenchmarkRoleError> for AdapterError {
        fn from(_: BenchmarkRoleError) -> Self {
            Self::Role
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct DeploymentId(String);

    impl DeploymentId {
        pub(super) fn parse(raw: &str) -> Result<Self, AdapterError> {
            if raw.len() != 32
                || !raw
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || raw.bytes().all(|byte| byte == b'0')
            {
                return Err(AdapterError::DeploymentIdentity);
            }
            Ok(Self(raw.to_owned()))
        }

        pub(super) fn as_str(&self) -> &str {
            &self.0
        }

        pub(super) fn header_value(&self) -> Result<http::HeaderValue, AdapterError> {
            http::HeaderValue::from_str(self.as_str()).map_err(|_| AdapterError::DeploymentIdentity)
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(super) fn deployment_id(env: &Env) -> Result<DeploymentId, AdapterError> {
        let raw = env
            .var(BENCHMARK_DEPLOYMENT_ID)
            .map_err(|_| AdapterError::DeploymentIdentity)?
            .to_string();
        DeploymentId::parse(&raw)
    }

    pub(super) fn deployment_id_header(
        headers: &http::HeaderMap,
    ) -> Result<DeploymentId, AdapterError> {
        let mut values = headers.get_all(DEPLOYMENT_ID_HEADER).iter();
        let value = values.next().ok_or(AdapterError::DeploymentIdentity)?;
        if values.next().is_some() {
            return Err(AdapterError::DeploymentIdentity);
        }
        let raw = value
            .to_str()
            .map_err(|_| AdapterError::DeploymentIdentity)?;
        DeploymentId::parse(raw)
    }

    pub(super) fn require_matching_deployment_id_header(
        headers: &http::HeaderMap,
        expected: &DeploymentId,
    ) -> Result<(), AdapterError> {
        if deployment_id_header(headers)? != *expected {
            return Err(AdapterError::DeploymentIdentity);
        }
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    fn validate_deriver_b_response_identity(
        status: http::StatusCode,
        headers: &http::HeaderMap,
        expected: &DeploymentId,
    ) -> Result<(), AdapterError> {
        if status == http::StatusCode::PRECONDITION_FAILED {
            return Err(AdapterError::DeploymentIdentity);
        }
        if status != http::StatusCode::OK {
            return Err(AdapterError::PeerStatus);
        }
        require_matching_deployment_id_header(headers, expected)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Colo(String);

    impl Colo {
        pub(super) fn parse(raw: &str) -> Result<Self, AdapterError> {
            if raw.len() != 3 || !raw.bytes().all(|byte| byte.is_ascii_uppercase()) {
                return Err(AdapterError::PlacementEvidence);
            }
            Ok(Self(raw.to_owned()))
        }

        pub(super) fn as_str(&self) -> &str {
            &self.0
        }

        pub(super) fn header_value(&self) -> Result<http::HeaderValue, AdapterError> {
            http::HeaderValue::from_str(self.as_str()).map_err(|_| AdapterError::PlacementEvidence)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct PlacementEvidence {
        deriver_a_colo: Option<Colo>,
        deriver_b_colo: Option<Colo>,
    }

    impl PlacementEvidence {
        pub(super) const fn new(
            deriver_a_colo: Option<Colo>,
            deriver_b_colo: Option<Colo>,
        ) -> Self {
            Self {
                deriver_a_colo,
                deriver_b_colo,
            }
        }

        pub(super) const fn deriver_a_colo(&self) -> Option<&Colo> {
            self.deriver_a_colo.as_ref()
        }

        pub(super) const fn deriver_b_colo(&self) -> Option<&Colo> {
            self.deriver_b_colo.as_ref()
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    trait IoBoundaryClock {
        fn now_ms(&self) -> f64;
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    struct WorkerIoBoundaryClock;

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl IoBoundaryClock for WorkerIoBoundaryClock {
        fn now_ms(&self) -> f64 {
            worker::js_sys::Date::now()
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    #[derive(Debug, Clone, Copy, Default, PartialEq)]
    struct TimingMilestones {
        last_observed_ms: Option<f64>,
        b_response_headers_received_ms: Option<f64>,
        b_to_a_first_body_byte_received_ms: Option<f64>,
        b_to_a_final_body_byte_received_ms: Option<f64>,
        offer_received_ms: Option<f64>,
        a_to_b_first_body_byte_emitted_ms: Option<f64>,
        a_to_b_final_body_byte_emitted_ms: Option<f64>,
        extension_received_ms: Option<f64>,
        first_table_frame_accepted_ms: Option<f64>,
        last_table_frame_accepted_ms: Option<f64>,
        translation_accepted_ms: Option<f64>,
        request_direction_closed_ms: Option<f64>,
        returned_received_ms: Option<f64>,
        response_eof_complete_ms: Option<f64>,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub(super) struct TransportPhaseTimings {
        b_response_headers_received_ms: f64,
        b_to_a_first_body_byte_received_ms: f64,
        offer_received_ms: f64,
        a_to_b_first_body_byte_emitted_ms: f64,
        extension_received_ms: f64,
        first_table_frame_accepted_ms: f64,
        last_table_frame_accepted_ms: f64,
        translation_accepted_ms: f64,
        a_to_b_final_body_byte_emitted_ms: f64,
        request_direction_closed_ms: f64,
        b_to_a_final_body_byte_received_ms: f64,
        returned_received_ms: f64,
        response_eof_complete_ms: f64,
        table_stream_duration_ms: f64,
        total_protocol_duration_ms: f64,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    impl TransportPhaseTimings {
        pub(super) const fn b_response_headers_received_ms(self) -> f64 {
            self.b_response_headers_received_ms
        }

        pub(super) const fn offer_received_ms(self) -> f64 {
            self.offer_received_ms
        }

        pub(super) const fn b_to_a_first_body_byte_received_ms(self) -> f64 {
            self.b_to_a_first_body_byte_received_ms
        }

        pub(super) const fn a_to_b_first_body_byte_emitted_ms(self) -> f64 {
            self.a_to_b_first_body_byte_emitted_ms
        }

        pub(super) const fn extension_received_ms(self) -> f64 {
            self.extension_received_ms
        }

        pub(super) const fn first_table_frame_accepted_ms(self) -> f64 {
            self.first_table_frame_accepted_ms
        }

        pub(super) const fn last_table_frame_accepted_ms(self) -> f64 {
            self.last_table_frame_accepted_ms
        }

        pub(super) const fn translation_accepted_ms(self) -> f64 {
            self.translation_accepted_ms
        }

        pub(super) const fn request_direction_closed_ms(self) -> f64 {
            self.request_direction_closed_ms
        }

        pub(super) const fn a_to_b_final_body_byte_emitted_ms(self) -> f64 {
            self.a_to_b_final_body_byte_emitted_ms
        }

        pub(super) const fn b_to_a_final_body_byte_received_ms(self) -> f64 {
            self.b_to_a_final_body_byte_received_ms
        }

        pub(super) const fn returned_received_ms(self) -> f64 {
            self.returned_received_ms
        }

        pub(super) const fn response_eof_complete_ms(self) -> f64 {
            self.response_eof_complete_ms
        }

        pub(super) const fn table_stream_duration_ms(self) -> f64 {
            self.table_stream_duration_ms
        }

        pub(super) const fn total_protocol_duration_ms(self) -> f64 {
            self.total_protocol_duration_ms
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TimingEvent {
        BResponseHeadersReceived,
        BToABodyByteReceived,
        OfferReceived,
        AToBBodyByteEmitted,
        ExtensionReceived,
        TableFrameAccepted,
        TranslationAccepted,
        RequestDirectionClosed,
        ReturnedReceived,
        ResponseEofComplete,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    #[derive(Clone)]
    struct TransportTimingRecorder {
        clock: Rc<dyn IoBoundaryClock>,
        started_ms: f64,
        milestones: Rc<RefCell<TimingMilestones>>,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    impl TransportTimingRecorder {
        fn new(clock: Rc<dyn IoBoundaryClock>) -> Result<Self, AdapterError> {
            let started_ms = clock.now_ms();
            if !started_ms.is_finite() || started_ms < 0.0 {
                return Err(AdapterError::TimingEvidence);
            }
            Ok(Self {
                clock,
                started_ms,
                milestones: Rc::new(RefCell::new(TimingMilestones::default())),
            })
        }

        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        fn worker() -> Result<Self, AdapterError> {
            Self::new(Rc::new(WorkerIoBoundaryClock))
        }

        fn mark(&self, event: TimingEvent) -> Result<(), AdapterError> {
            let now_ms = self.clock.now_ms();
            let elapsed_ms = now_ms - self.started_ms;
            if !now_ms.is_finite() || !elapsed_ms.is_finite() || elapsed_ms < 0.0 {
                return Err(AdapterError::TimingEvidence);
            }
            let mut milestones = self
                .milestones
                .try_borrow_mut()
                .map_err(|_| AdapterError::TimingEvidence)?;
            if milestones
                .last_observed_ms
                .is_some_and(|previous_ms| previous_ms > elapsed_ms)
            {
                return Err(AdapterError::TimingEvidence);
            }
            milestones.last_observed_ms = Some(elapsed_ms);
            match event {
                TimingEvent::BResponseHeadersReceived => {
                    set_once(&mut milestones.b_response_headers_received_ms, elapsed_ms)?;
                }
                TimingEvent::BToABodyByteReceived => {
                    milestones
                        .b_to_a_first_body_byte_received_ms
                        .get_or_insert(elapsed_ms);
                    milestones.b_to_a_final_body_byte_received_ms = Some(elapsed_ms);
                }
                TimingEvent::OfferReceived => {
                    set_once(&mut milestones.offer_received_ms, elapsed_ms)?;
                }
                TimingEvent::AToBBodyByteEmitted => {
                    milestones
                        .a_to_b_first_body_byte_emitted_ms
                        .get_or_insert(elapsed_ms);
                    milestones.a_to_b_final_body_byte_emitted_ms = Some(elapsed_ms);
                }
                TimingEvent::ExtensionReceived => {
                    set_once(&mut milestones.extension_received_ms, elapsed_ms)?;
                }
                TimingEvent::TableFrameAccepted => {
                    if milestones.first_table_frame_accepted_ms.is_none() {
                        milestones.first_table_frame_accepted_ms = Some(elapsed_ms);
                    }
                    milestones.last_table_frame_accepted_ms = Some(elapsed_ms);
                }
                TimingEvent::TranslationAccepted => {
                    set_once(&mut milestones.translation_accepted_ms, elapsed_ms)?;
                }
                TimingEvent::RequestDirectionClosed => {
                    set_once(&mut milestones.request_direction_closed_ms, elapsed_ms)?;
                }
                TimingEvent::ReturnedReceived => {
                    set_once(&mut milestones.returned_received_ms, elapsed_ms)?;
                }
                TimingEvent::ResponseEofComplete => {
                    set_once(&mut milestones.response_eof_complete_ms, elapsed_ms)?;
                }
            }
            Ok(())
        }

        fn finish(&self) -> Result<TransportPhaseTimings, AdapterError> {
            let milestones = *self
                .milestones
                .try_borrow()
                .map_err(|_| AdapterError::TimingEvidence)?;
            let values = [
                required(milestones.b_response_headers_received_ms)?,
                required(milestones.b_to_a_first_body_byte_received_ms)?,
                required(milestones.offer_received_ms)?,
                required(milestones.a_to_b_first_body_byte_emitted_ms)?,
                required(milestones.extension_received_ms)?,
                required(milestones.first_table_frame_accepted_ms)?,
                required(milestones.last_table_frame_accepted_ms)?,
                required(milestones.translation_accepted_ms)?,
                required(milestones.a_to_b_final_body_byte_emitted_ms)?,
                required(milestones.request_direction_closed_ms)?,
                required(milestones.b_to_a_final_body_byte_received_ms)?,
                required(milestones.returned_received_ms)?,
                required(milestones.response_eof_complete_ms)?,
            ];
            if values
                .windows(2)
                .any(|pair| pair[0] > pair[1] || !pair[0].is_finite())
                || !values[12].is_finite()
            {
                return Err(AdapterError::TimingEvidence);
            }
            Ok(TransportPhaseTimings {
                b_response_headers_received_ms: values[0],
                b_to_a_first_body_byte_received_ms: values[1],
                offer_received_ms: values[2],
                a_to_b_first_body_byte_emitted_ms: values[3],
                extension_received_ms: values[4],
                first_table_frame_accepted_ms: values[5],
                last_table_frame_accepted_ms: values[6],
                translation_accepted_ms: values[7],
                a_to_b_final_body_byte_emitted_ms: values[8],
                request_direction_closed_ms: values[9],
                b_to_a_final_body_byte_received_ms: values[10],
                returned_received_ms: values[11],
                response_eof_complete_ms: values[12],
                table_stream_duration_ms: values[6] - values[5],
                total_protocol_duration_ms: values[12],
            })
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    fn set_once(slot: &mut Option<f64>, value: f64) -> Result<(), AdapterError> {
        if slot.replace(value).is_some() {
            return Err(AdapterError::TimingEvidence);
        }
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    fn required(value: Option<f64>) -> Result<f64, AdapterError> {
        value.ok_or(AdapterError::TimingEvidence)
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    pub(super) fn incoming_colo(
        request: &worker::HttpRequest,
    ) -> Result<Option<Colo>, AdapterError> {
        request
            .extensions()
            .get::<worker::Cf>()
            .map(|cf| Colo::parse(&cf.colo()))
            .transpose()
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(super) fn raw_incoming_colo(
        request: &worker::web_sys::Request,
    ) -> Result<Option<Colo>, AdapterError> {
        use worker_sys::ext::RequestExt;

        let Some(cf) = request.cf() else {
            return Ok(None);
        };
        let colo = cf.colo().map_err(|_| AdapterError::PlacementEvidence)?;
        Colo::parse(&colo).map(Some)
    }

    pub(super) fn optional_colo_header(
        headers: &http::HeaderMap,
        name: &'static str,
    ) -> Result<Option<Colo>, AdapterError> {
        let mut values = headers.get_all(name).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(AdapterError::PlacementEvidence);
        }
        let raw = value
            .to_str()
            .map_err(|_| AdapterError::PlacementEvidence)?;
        Colo::parse(raw).map(Some)
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(super) struct AdapterIoMetrics {
        total_incoming_body_bytes: u64,
        max_incoming_platform_fragment_bytes: usize,
        adapter_secret_ingress_rust_copy_bytes: u64,
        adapter_secret_ingress_js_overwrite_bytes: u64,
        total_outgoing_envelope_bytes: u64,
        peak_outgoing_envelope_bytes: usize,
        workers_rs_outgoing_stream_body_copy_bytes: u64,
        injected_outgoing_fragment_count: u64,
        max_injected_outgoing_fragment_bytes: usize,
    }

    impl AdapterIoMetrics {
        fn record_incoming_fragment(&mut self, fragment_bytes: usize) -> Result<(), AdapterError> {
            let fragment_bytes =
                u64::try_from(fragment_bytes).map_err(|_| AdapterError::MeasurementOverflow)?;
            self.total_incoming_body_bytes = self
                .total_incoming_body_bytes
                .checked_add(fragment_bytes)
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.adapter_secret_ingress_rust_copy_bytes = self
                .adapter_secret_ingress_rust_copy_bytes
                .checked_add(fragment_bytes)
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.adapter_secret_ingress_js_overwrite_bytes = self
                .adapter_secret_ingress_js_overwrite_bytes
                .checked_add(fragment_bytes)
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.max_incoming_platform_fragment_bytes =
                self.max_incoming_platform_fragment_bytes.max(
                    usize::try_from(fragment_bytes)
                        .map_err(|_| AdapterError::MeasurementOverflow)?,
                );
            Ok(())
        }

        fn record_outgoing_envelope(&mut self, envelope_bytes: usize) -> Result<(), AdapterError> {
            let envelope_bytes =
                u64::try_from(envelope_bytes).map_err(|_| AdapterError::MeasurementOverflow)?;
            self.total_outgoing_envelope_bytes = self
                .total_outgoing_envelope_bytes
                .checked_add(envelope_bytes)
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.workers_rs_outgoing_stream_body_copy_bytes = self
                .workers_rs_outgoing_stream_body_copy_bytes
                .checked_add(
                    envelope_bytes
                        .checked_mul(WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES)
                        .ok_or(AdapterError::MeasurementOverflow)?,
                )
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.peak_outgoing_envelope_bytes = self.peak_outgoing_envelope_bytes.max(
                usize::try_from(envelope_bytes).map_err(|_| AdapterError::MeasurementOverflow)?,
            );
            Ok(())
        }

        #[cfg(feature = "fault-fragmentation")]
        fn record_injected_outgoing_fragment(
            &mut self,
            fragment_bytes: usize,
        ) -> Result<(), AdapterError> {
            self.injected_outgoing_fragment_count = self
                .injected_outgoing_fragment_count
                .checked_add(1)
                .ok_or(AdapterError::MeasurementOverflow)?;
            self.max_injected_outgoing_fragment_bytes = self
                .max_injected_outgoing_fragment_bytes
                .max(fragment_bytes);
            Ok(())
        }

        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        pub(super) fn merge(self, other: Self) -> Result<Self, AdapterError> {
            Ok(Self {
                total_incoming_body_bytes: self
                    .total_incoming_body_bytes
                    .checked_add(other.total_incoming_body_bytes)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                max_incoming_platform_fragment_bytes: self
                    .max_incoming_platform_fragment_bytes
                    .max(other.max_incoming_platform_fragment_bytes),
                adapter_secret_ingress_rust_copy_bytes: self
                    .adapter_secret_ingress_rust_copy_bytes
                    .checked_add(other.adapter_secret_ingress_rust_copy_bytes)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                adapter_secret_ingress_js_overwrite_bytes: self
                    .adapter_secret_ingress_js_overwrite_bytes
                    .checked_add(other.adapter_secret_ingress_js_overwrite_bytes)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                total_outgoing_envelope_bytes: self
                    .total_outgoing_envelope_bytes
                    .checked_add(other.total_outgoing_envelope_bytes)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                peak_outgoing_envelope_bytes: self
                    .peak_outgoing_envelope_bytes
                    .max(other.peak_outgoing_envelope_bytes),
                workers_rs_outgoing_stream_body_copy_bytes: self
                    .workers_rs_outgoing_stream_body_copy_bytes
                    .checked_add(other.workers_rs_outgoing_stream_body_copy_bytes)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                injected_outgoing_fragment_count: self
                    .injected_outgoing_fragment_count
                    .checked_add(other.injected_outgoing_fragment_count)
                    .ok_or(AdapterError::MeasurementOverflow)?,
                max_injected_outgoing_fragment_bytes: self
                    .max_injected_outgoing_fragment_bytes
                    .max(other.max_injected_outgoing_fragment_bytes),
            })
        }

        pub(super) const fn total_incoming_body_bytes(self) -> u64 {
            self.total_incoming_body_bytes
        }

        pub(super) const fn max_incoming_platform_fragment_bytes(self) -> usize {
            self.max_incoming_platform_fragment_bytes
        }

        pub(super) const fn adapter_secret_ingress_rust_copy_bytes(self) -> u64 {
            self.adapter_secret_ingress_rust_copy_bytes
        }

        pub(super) const fn adapter_secret_ingress_js_overwrite_bytes(self) -> u64 {
            self.adapter_secret_ingress_js_overwrite_bytes
        }

        pub(super) const fn total_outgoing_envelope_bytes(self) -> u64 {
            self.total_outgoing_envelope_bytes
        }

        pub(super) const fn peak_outgoing_envelope_bytes(self) -> usize {
            self.peak_outgoing_envelope_bytes
        }

        pub(super) const fn workers_rs_outgoing_stream_body_copy_bytes(self) -> u64 {
            self.workers_rs_outgoing_stream_body_copy_bytes
        }

        pub(super) const fn injected_outgoing_fragment_count(self) -> u64 {
            self.injected_outgoing_fragment_count
        }

        pub(super) const fn max_injected_outgoing_fragment_bytes(self) -> usize {
            self.max_injected_outgoing_fragment_bytes
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) enum InboundTransportEvent {
        Message(WireMessage),
        Eof(DirectionalEofEvidence),
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    struct YaoDuplexTransportCompletion {
        io_metrics: AdapterIoMetrics,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    trait YaoDuplexTransport {
        async fn send(
            &mut self,
            message: WireMessage,
        ) -> Result<Option<InboundTransportEvent>, AdapterError>;

        async fn receive(&mut self) -> Result<InboundTransportEvent, AdapterError>;

        async fn close_local_direction(
            &mut self,
        ) -> Result<(DirectionalEofEvidence, Option<InboundTransportEvent>), AdapterError>;

        async fn finish(self) -> Result<YaoDuplexTransportCompletion, AdapterError>;
    }

    struct EnvelopeDecoder {
        inner: DirectionalWireDecoder,
        message: Option<WireMessage>,
    }

    impl EnvelopeDecoder {
        fn new(direction: WireDirection, session: [u8; 32]) -> Result<Self, AdapterError> {
            Ok(Self {
                inner: DirectionalWireDecoder::new(direction, session)?,
                message: None,
            })
        }

        fn push_once(&mut self, fragment: &[u8]) -> Result<usize, AdapterError> {
            if fragment.is_empty() || self.message.is_some() {
                return Err(AdapterError::ProtocolState);
            }
            let consumed = self
                .inner
                .push(fragment)
                .map_err(|_| AdapterError::Envelope)?;
            if consumed == 0 {
                return Err(AdapterError::Envelope);
            }
            self.message = self
                .inner
                .take_message()
                .map_err(|_| AdapterError::Envelope)?;
            Ok(consumed)
        }

        fn pop_message(&mut self) -> Option<WireMessage> {
            self.message.take()
        }

        fn finish(self) -> Result<DirectionalEofEvidence, AdapterError> {
            if self.message.is_some() {
                return Err(AdapterError::ProtocolState);
            }
            self.inner
                .finish_at_transport_eof()
                .map_err(|_| AdapterError::Envelope)
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) struct OutboundDirectionClose {
        pub(super) evidence: DirectionalEofEvidence,
        pub(super) metrics: AdapterIoMetrics,
    }

    #[cfg(feature = "fault-fragmentation")]
    struct DeterministicFragments {
        envelope: Bytes,
        offset: usize,
        width_index: usize,
    }

    #[cfg(feature = "fault-fragmentation")]
    impl DeterministicFragments {
        fn new(envelope: Bytes) -> Self {
            Self {
                envelope,
                offset: 0,
                width_index: 0,
            }
        }

        fn next(&mut self) -> Option<Bytes> {
            const WIDTHS: [usize; 5] = [1, 7, 31, 257, 4096];
            if self.offset == self.envelope.len() {
                return None;
            }
            let width = WIDTHS[self.width_index % WIDTHS.len()];
            let end = self.offset.saturating_add(width).min(self.envelope.len());
            let fragment = self.envelope.slice(self.offset..end);
            self.offset = end;
            self.width_index += 1;
            Some(fragment)
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) struct OutboundEnvelopeStream {
        receiver: mpsc::Receiver<WireMessage>,
        encoder: Option<DirectionalWireEncoder>,
        eof_sender: Option<oneshot::Sender<Result<OutboundDirectionClose, AdapterError>>>,
        timing: TransportTimingRecorder,
        metrics: AdapterIoMetrics,
        #[cfg(feature = "fault-fragmentation")]
        pending_fragments: Option<DeterministicFragments>,
        #[cfg(feature = "fault-request-disconnect-after-base-choices")]
        disconnect_after_current: bool,
        terminated: bool,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl OutboundEnvelopeStream {
        fn new(
            session: [u8; 32],
            receiver: mpsc::Receiver<WireMessage>,
            eof_sender: oneshot::Sender<Result<OutboundDirectionClose, AdapterError>>,
            timing: TransportTimingRecorder,
        ) -> Result<Self, AdapterError> {
            Ok(Self {
                receiver,
                encoder: Some(DirectionalWireEncoder::new(
                    WireDirection::DeriverAToDeriverB,
                    session,
                )?),
                eof_sender: Some(eof_sender),
                timing,
                metrics: AdapterIoMetrics::default(),
                #[cfg(feature = "fault-fragmentation")]
                pending_fragments: None,
                #[cfg(feature = "fault-request-disconnect-after-base-choices")]
                disconnect_after_current: false,
                terminated: false,
            })
        }

        fn finish_at_body_end(&mut self) {
            let evidence = self
                .encoder
                .take()
                .ok_or(AdapterError::ProtocolState)
                .and_then(|encoder| finish_encoder(encoder, self.metrics))
                .and_then(|closed| {
                    self.timing.mark(TimingEvent::RequestDirectionClosed)?;
                    Ok(closed)
                });
            if let Some(sender) = self.eof_sender.take() {
                let _ignored_receiver = sender.send(evidence);
            }
            self.terminated = true;
        }

        fn fail(
            &mut self,
            error: AdapterError,
        ) -> Poll<Option<Result<Frame<Bytes>, AdapterError>>> {
            if let Some(sender) = self.eof_sender.take() {
                let _ignored_receiver = sender.send(Err(error));
            }
            self.encoder.take();
            self.terminated = true;
            Poll::Ready(Some(Err(error)))
        }

        fn emit_data(
            &mut self,
            fragment: Bytes,
        ) -> Poll<Option<Result<Frame<Bytes>, AdapterError>>> {
            if let Err(error) = self.timing.mark(TimingEvent::AToBBodyByteEmitted) {
                return self.fail(error);
            }
            Poll::Ready(Some(Ok(Frame::data(fragment))))
        }

        #[cfg(feature = "fault-request-disconnect-after-base-choices")]
        fn disconnect_request(&mut self) -> Poll<Option<Result<Frame<Bytes>, AdapterError>>> {
            self.receiver.close();
            if let Some(sender) = self.eof_sender.take() {
                let _ignored_receiver = sender.send(Err(AdapterError::InjectedRequestDisconnect));
            }
            self.encoder.take();
            self.terminated = true;
            Poll::Ready(Some(Err(AdapterError::InjectedRequestDisconnect)))
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn finish_encoder(
        encoder: DirectionalWireEncoder,
        metrics: AdapterIoMetrics,
    ) -> Result<OutboundDirectionClose, AdapterError> {
        Ok(OutboundDirectionClose {
            evidence: encoder.finish_after_transport_close()?,
            metrics,
        })
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl Stream for OutboundEnvelopeStream {
        type Item = Result<Frame<Bytes>, AdapterError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.terminated {
                return Poll::Ready(None);
            }
            #[cfg(feature = "fault-fragmentation")]
            if let Some(fragments) = self.pending_fragments.as_mut() {
                if let Some(fragment) = fragments.next() {
                    if self
                        .metrics
                        .record_injected_outgoing_fragment(fragment.len())
                        .is_err()
                    {
                        return self.fail(AdapterError::MeasurementOverflow);
                    }
                    return self.emit_data(fragment);
                }
                self.pending_fragments = None;
            }
            #[cfg(feature = "fault-request-disconnect-after-base-choices")]
            if self.disconnect_after_current {
                return self.disconnect_request();
            }
            match Pin::new(&mut self.receiver).poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(message)) => {
                    let message_kind = message.kind();
                    let timing_result = match message_kind {
                        WireMessageKind::TableFrame => {
                            self.timing.mark(TimingEvent::TableFrameAccepted)
                        }
                        WireMessageKind::OutputTranslation => {
                            self.timing.mark(TimingEvent::TranslationAccepted)
                        }
                        _ => Ok(()),
                    };
                    if let Err(error) = timing_result {
                        return self.fail(error);
                    }
                    let Some(encoder) = self.encoder.as_mut() else {
                        return self.fail(AdapterError::ProtocolState);
                    };
                    match encoder.encode(message) {
                        Ok(envelope) => {
                            if self
                                .metrics
                                .record_outgoing_envelope(envelope.len())
                                .is_err()
                            {
                                return self.fail(AdapterError::MeasurementOverflow);
                            }
                            #[cfg(feature = "fault-request-disconnect-after-base-choices")]
                            if message_kind == WireMessageKind::BaseOtChoices {
                                self.disconnect_after_current = true;
                            }
                            let envelope = Bytes::from_owner(Zeroizing::new(envelope));
                            #[cfg(feature = "fault-fragmentation")]
                            {
                                let mut fragments = DeterministicFragments::new(envelope);
                                let fragment = fragments
                                    .next()
                                    .expect("encoded envelopes are always non-empty");
                                if self
                                    .metrics
                                    .record_injected_outgoing_fragment(fragment.len())
                                    .is_err()
                                {
                                    return self.fail(AdapterError::MeasurementOverflow);
                                }
                                self.pending_fragments = Some(fragments);
                                self.emit_data(fragment)
                            }
                            #[cfg(not(feature = "fault-fragmentation"))]
                            self.emit_data(envelope)
                        }
                        Err(_) => self.fail(AdapterError::OutboundBody),
                    }
                }
                Poll::Ready(None) => {
                    self.finish_at_body_end();
                    Poll::Ready(None)
                }
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl Drop for OutboundEnvelopeStream {
        fn drop(&mut self) {
            if self.terminated {
                return;
            }
            if let Some(sender) = self.eof_sender.take() {
                let _ignored_receiver = sender.send(Err(AdapterError::OutboundEof));
            }
            self.encoder.take();
            self.terminated = true;
        }
    }

    pub(super) struct SecretIncomingBody {
        inner: Pin<Box<dyn Stream<Item = Result<Bytes, AdapterError>>>>,
    }

    impl SecretIncomingBody {
        #[cfg(any(feature = "deriver-a", feature = "deriver-b"))]
        pub(super) fn new(stream: worker::web_sys::ReadableStream) -> Result<Self, AdapterError> {
            let readable = wasm_streams::ReadableStream::from_raw(stream.unchecked_into());
            let inner = readable
                .try_into_stream()
                .map_err(|_| AdapterError::InboundBody)?
                .map(secret_chunk_from_js);
            Ok(Self {
                inner: Box::pin(inner),
            })
        }

        #[cfg(any(
            feature = "deriver-b",
            feature = "deriver-b-cross-account",
            feature = "deriver-b-same-account-websocket",
            test
        ))]
        pub(super) fn empty() -> Self {
            Self {
                inner: Box::pin(futures_util::stream::empty()),
            }
        }
    }

    #[cfg(any(feature = "deriver-a", feature = "deriver-b"))]
    fn secret_chunk_from_js(
        item: Result<worker::wasm_bindgen::JsValue, worker::wasm_bindgen::JsValue>,
    ) -> Result<Bytes, AdapterError> {
        let chunk = item
            .map_err(|_| AdapterError::InboundBody)?
            .dyn_into::<worker::js_sys::Uint8Array>()
            .map_err(|_| AdapterError::InboundBody)?;
        let chunk_len = usize::try_from(chunk.length()).map_err(|_| AdapterError::InboundBody)?;
        let mut owner = Zeroizing::new(vec![0_u8; chunk_len]);
        chunk.copy_to(owner.as_mut_slice());
        chunk.fill(0, 0, chunk.length());
        Ok(Bytes::from_owner(owner))
    }

    impl Stream for SecretIncomingBody {
        type Item = Result<Bytes, AdapterError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.inner.as_mut().poll_next(cx)
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    struct InboundEnvelopeBody {
        body: SecretIncomingBody,
        timing: TransportTimingRecorder,
        decoder: Option<EnvelopeDecoder>,
        fragment: Option<Bytes>,
        fragment_offset: usize,
        metrics: AdapterIoMetrics,
        ended: bool,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl InboundEnvelopeBody {
        fn new(
            body: SecretIncomingBody,
            session: [u8; 32],
            timing: TransportTimingRecorder,
        ) -> Result<Self, AdapterError> {
            Ok(Self {
                body,
                timing,
                decoder: Some(EnvelopeDecoder::new(
                    WireDirection::DeriverBToDeriverA,
                    session,
                )?),
                fragment: None,
                fragment_offset: 0,
                metrics: AdapterIoMetrics::default(),
                ended: false,
            })
        }

        const fn metrics(&self) -> AdapterIoMetrics {
            self.metrics
        }

        async fn next_event(&mut self) -> Result<InboundTransportEvent, AdapterError> {
            loop {
                let decoder = self.decoder.as_mut().ok_or(AdapterError::ProtocolState)?;
                if let Some(message) = decoder.pop_message() {
                    return Ok(InboundTransportEvent::Message(message));
                }
                if let Some(fragment) = self.fragment.as_ref() {
                    let consumed = decoder.push_once(&fragment[self.fragment_offset..])?;
                    self.fragment_offset += consumed;
                    if self.fragment_offset == fragment.len() {
                        self.fragment = None;
                        self.fragment_offset = 0;
                    }
                    continue;
                }
                if self.ended {
                    return Err(AdapterError::ProtocolState);
                }
                match self.body.next().await {
                    Some(Ok(fragment)) if fragment.is_empty() => {}
                    Some(Ok(fragment)) => {
                        self.timing.mark(TimingEvent::BToABodyByteReceived)?;
                        self.metrics.record_incoming_fragment(fragment.len())?;
                        self.fragment = Some(fragment);
                        self.fragment_offset = 0;
                    }
                    Some(Err(_)) => return Err(AdapterError::InboundBody),
                    None => {
                        self.ended = true;
                        let decoder = self.decoder.take().ok_or(AdapterError::ProtocolState)?;
                        return Ok(InboundTransportEvent::Eof(decoder.finish()?));
                    }
                }
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    enum AProgress {
        Continue(Activation128KiBDeriverA),
        Send {
            role: Activation128KiBDeriverA,
            message: WireMessage,
        },
        Complete(ActivationDeriverACompletion),
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) struct DeriverABenchmarkCompletion {
        completion: ActivationDeriverACompletion,
        deployment_id: DeploymentId,
        io_metrics: AdapterIoMetrics,
        placement: PlacementEvidence,
        timings: TransportPhaseTimings,
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl DeriverABenchmarkCompletion {
        pub(super) const fn completion(&self) -> &ActivationDeriverACompletion {
            &self.completion
        }

        pub(super) const fn deployment_id(&self) -> &DeploymentId {
            &self.deployment_id
        }

        pub(super) const fn io_metrics(&self) -> AdapterIoMetrics {
            self.io_metrics
        }

        pub(super) const fn placement(&self) -> &PlacementEvidence {
            &self.placement
        }

        pub(super) const fn timings(&self) -> TransportPhaseTimings {
            self.timings
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn validate_deriver_a_wire_bytes(
        completion: &ActivationDeriverACompletion,
        metrics: AdapterIoMetrics,
    ) -> Result<(), AdapterError> {
        let ledger = completion.wire_byte_ledger();
        if metrics.total_outgoing_envelope_bytes() != ledger.deriver_a_to_b_transport_bytes()
            || metrics.total_incoming_body_bytes() != ledger.deriver_b_to_a_transport_bytes()
        {
            return Err(AdapterError::WireAccounting);
        }
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    fn validate_deriver_b_wire_bytes(
        completion: &ActivationDeriverBCompletion,
        metrics: AdapterIoMetrics,
    ) -> Result<(), AdapterError> {
        let ledger = completion.wire_byte_ledger();
        if metrics.total_incoming_body_bytes() != ledger.deriver_a_to_b_transport_bytes()
            || metrics.total_outgoing_envelope_bytes() != ledger.deriver_b_to_a_transport_bytes()
        {
            return Err(AdapterError::WireAccounting);
        }
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn advance_a(
        role: Activation128KiBDeriverA,
        event: RelayEvent,
    ) -> Result<AProgress, AdapterError> {
        Ok(match role.handle(event)? {
            RelayStep::Continue(role) => AProgress::Continue(role),
            RelayStep::Send { role, message } => AProgress::Send { role, message },
            RelayStep::Complete(completion) => AProgress::Complete(completion),
        })
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    async fn send_while_polling_peer(
        sender: &mut mpsc::Sender<WireMessage>,
        message: WireMessage,
        inbound: &mut InboundEnvelopeBody,
    ) -> Result<Option<InboundTransportEvent>, AdapterError> {
        let send_future = Box::pin(sender.send(message));
        let inbound_future = Box::pin(inbound.next_event());
        match select(send_future, inbound_future).await {
            FutureEither::Left((send_result, _inbound_future)) => {
                if send_result.is_err() {
                    return Err(AdapterError::OutboundClosed);
                }
                Ok(None)
            }
            FutureEither::Right((event, send_future)) => {
                let event = event?;
                if send_future.await.is_err() {
                    return Err(AdapterError::OutboundClosed);
                }
                Ok(Some(event))
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn resolve_local_eof(
        result: Result<Result<OutboundDirectionClose, AdapterError>, oneshot::Canceled>,
    ) -> Result<OutboundDirectionClose, AdapterError> {
        result.map_err(|_| AdapterError::OutboundEof)?
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    async fn close_while_polling_peer(
        sender: mpsc::Sender<WireMessage>,
        eof_receiver: oneshot::Receiver<Result<OutboundDirectionClose, AdapterError>>,
        inbound: &mut InboundEnvelopeBody,
    ) -> Result<(OutboundDirectionClose, Option<InboundTransportEvent>), AdapterError> {
        drop(sender);
        let eof_future = Box::pin(eof_receiver);
        let inbound_future = Box::pin(inbound.next_event());
        match select(eof_future, inbound_future).await {
            FutureEither::Left((evidence, _inbound_future)) => {
                Ok((resolve_local_eof(evidence)?, None))
            }
            FutureEither::Right((event, eof_future)) => {
                let event = event?;
                Ok((resolve_local_eof(eof_future.await)?, Some(event)))
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn push_deferred_transport_event(
        deferred: &mut VecDeque<InboundTransportEvent>,
        event: InboundTransportEvent,
    ) -> Result<(), AdapterError> {
        if !deferred.is_empty() {
            return Err(AdapterError::ProtocolState);
        }
        deferred.push_back(event);
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    async fn next_a_transport_event<T: YaoDuplexTransport>(
        deferred: &mut VecDeque<InboundTransportEvent>,
        transport: &mut T,
    ) -> Result<InboundTransportEvent, AdapterError> {
        if let Some(event) = deferred.pop_front() {
            return Ok(event);
        }
        transport.receive().await
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn mark_deriver_a_receive_timing(
        timing: &TransportTimingRecorder,
        kind: WireMessageKind,
    ) -> Result<(), AdapterError> {
        match kind {
            WireMessageKind::BaseOtOffer => timing.mark(TimingEvent::OfferReceived),
            WireMessageKind::OtExtensionMatrix => timing.mark(TimingEvent::ExtensionReceived),
            WireMessageKind::ReturnedOutputLabels => timing.mark(TimingEvent::ReturnedReceived),
            _ => Ok(()),
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    fn accept_a_continue(progress: AProgress) -> Result<Activation128KiBDeriverA, AdapterError> {
        match progress {
            AProgress::Continue(role) => Ok(role),
            AProgress::Send { .. } | AProgress::Complete(_) => Err(AdapterError::ProtocolState),
        }
    }

    fn validate_inbound_message(
        message: &WireMessage,
        expected_kind: WireMessageKind,
        expected_payload_bytes: usize,
    ) -> Result<(), AdapterError> {
        if message.kind() != expected_kind || message.as_bytes().len() != expected_payload_bytes {
            return Err(AdapterError::Envelope);
        }
        Ok(())
    }

    #[cfg(any(feature = "deriver-a-cross-account", test))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CrossAccountWebSocketEndpoint {
        url: url::Url,
    }

    #[cfg(any(feature = "deriver-a-cross-account", test))]
    impl CrossAccountWebSocketEndpoint {
        fn parse(raw: &str) -> Result<Self, AdapterError> {
            let url = url::Url::parse(raw).map_err(|_| AdapterError::CrossAccountEndpoint)?;
            if url.scheme() != "wss"
                || !url.has_host()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != BENCHMARK_PATH
                || matches!(url.port(), Some(port) if port != 443)
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(AdapterError::CrossAccountEndpoint);
            }
            Ok(Self { url })
        }

        fn as_str(&self) -> &str {
            self.url.as_str()
        }

        fn url(&self) -> &url::Url {
            &self.url
        }
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    fn websocket_protocol(deployment_id: &DeploymentId, session: [u8; 32]) -> String {
        format!(
            "{WEBSOCKET_PROTOCOL_PREFIX}.{}.{}",
            deployment_id.as_str(),
            encode_session(session)
        )
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) fn parse_websocket_protocol(
        raw: &str,
    ) -> Result<(DeploymentId, [u8; 32]), AdapterError> {
        let mut parts = raw.split('.');
        let prefix = parts.next().ok_or(AdapterError::WebSocketProtocol)?;
        let deployment_id = parts.next().ok_or(AdapterError::WebSocketProtocol)?;
        let session = parts.next().ok_or(AdapterError::WebSocketProtocol)?;
        if prefix != WEBSOCKET_PROTOCOL_PREFIX || parts.next().is_some() {
            return Err(AdapterError::WebSocketProtocol);
        }
        Ok((
            DeploymentId::parse(deployment_id)?,
            decode_session(session)?,
        ))
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket"
    ))]
    enum WebSocketTransportEvent {
        Binary(Bytes),
        Closed,
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket"
    ))]
    async fn next_websocket_event(
        events: &mut worker::EventStream<'_>,
    ) -> Result<WebSocketTransportEvent, AdapterError> {
        match events.next().await {
            Some(Ok(worker::WebsocketEvent::Message(message))) => {
                let data = message.as_ref().data();
                if !data.is_object() {
                    return Err(AdapterError::WebSocketEvent);
                }
                let array = worker::js_sys::Uint8Array::new(&data);
                let length =
                    usize::try_from(array.length()).map_err(|_| AdapterError::WebSocketEvent)?;
                let mut bytes = Zeroizing::new(vec![0_u8; length]);
                array.copy_to(bytes.as_mut_slice());
                array.fill(0, 0, array.length());
                Ok(WebSocketTransportEvent::Binary(Bytes::from_owner(bytes)))
            }
            Some(Ok(worker::WebsocketEvent::Close(close)))
                if close.was_clean() && close.code() == 1000 =>
            {
                Ok(WebSocketTransportEvent::Closed)
            }
            Some(Ok(worker::WebsocketEvent::Close(close))) => {
                worker::console_error!(
                    "{{\"event\":\"ed25519_yao_websocket_closed\",\"code\":{},\"was_clean\":{},\"reason\":{:?}}}",
                    close.code(),
                    close.was_clean(),
                    close.reason(),
                );
                Err(AdapterError::WebSocketEvent)
            }
            Some(Err(error)) => {
                worker::console_error!(
                    "{{\"event\":\"ed25519_yao_websocket_error\",\"detail\":{:?}}}",
                    error,
                );
                Err(AdapterError::WebSocketEvent)
            }
            None => {
                worker::console_error!(
                    "{{\"event\":\"ed25519_yao_websocket_event_stream_ended\"}}"
                );
                Err(AdapterError::WebSocketEvent)
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket"
    ))]
    fn decode_websocket_envelope(
        decoder: &mut EnvelopeDecoder,
        payload: Bytes,
        metrics: &mut AdapterIoMetrics,
    ) -> Result<WireMessage, AdapterError> {
        if payload.is_empty() || payload.as_ref() == WEBSOCKET_DIRECTION_EOF {
            return Err(AdapterError::Envelope);
        }
        metrics.record_incoming_fragment(payload.len())?;
        let mut offset = 0;
        while offset < payload.len() {
            offset += decoder.push_once(&payload[offset..])?;
        }
        let message = decoder.pop_message().ok_or(AdapterError::Envelope)?;
        if decoder.pop_message().is_some() {
            return Err(AdapterError::Envelope);
        }
        Ok(message)
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-b-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-same-account-websocket"
    ))]
    fn send_websocket_envelope(
        socket: &worker::WebSocket,
        encoder: &mut DirectionalWireEncoder,
        message: WireMessage,
        metrics: &mut AdapterIoMetrics,
    ) -> Result<(), AdapterError> {
        let envelope = Zeroizing::new(
            encoder
                .encode(message)
                .map_err(|_| AdapterError::OutboundBody)?,
        );
        metrics.record_outgoing_envelope(envelope.len())?;
        socket
            .send_with_bytes(envelope.as_slice())
            .map_err(|_| AdapterError::WebSocketSend)
    }

    #[cfg(feature = "deriver-a-cross-account")]
    async fn connect_deriver_b_websocket(
        env: &Env,
        protocol: &str,
    ) -> Result<worker::WebSocket, AdapterError> {
        let raw_endpoint = env
            .var(DERIVER_B_WEBSOCKET_ENDPOINT)
            .map_err(|_| AdapterError::CrossAccountEndpoint)?
            .to_string();
        let endpoint = CrossAccountWebSocketEndpoint::parse(&raw_endpoint)?;
        worker::WebSocket::connect_with_protocols(endpoint.url().clone(), Some(vec![protocol]))
            .await
            .map_err(|_| AdapterError::WebSocketConnect)
    }

    #[cfg(feature = "deriver-a-same-account-websocket")]
    async fn connect_deriver_b_websocket(
        env: &Env,
        protocol: &str,
    ) -> Result<worker::WebSocket, AdapterError> {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(DERIVER_B_URL)
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::SEC_WEBSOCKET_PROTOCOL, protocol)
            .body(Body::empty())
            .map_err(|_| AdapterError::WebSocketConnect)?;
        let mut response = env
            .service(DERIVER_B_BINDING)
            .map_err(|_| AdapterError::ServiceBinding)?
            .fetch_request(request)
            .await
            .map_err(|_| AdapterError::WebSocketConnect)?;
        if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(AdapterError::PeerStatus);
        }
        let negotiated_protocol = response
            .headers()
            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .ok_or(AdapterError::WebSocketProtocol)?;
        if negotiated_protocol != protocol {
            return Err(AdapterError::WebSocketProtocol);
        }
        response
            .extensions_mut()
            .remove::<worker::WebSocket>()
            .ok_or(AdapterError::WebSocketConnect)
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    struct WebSocketYaoDuplexTransport<'socket> {
        socket: &'socket worker::WebSocket,
        events: worker::EventStream<'socket>,
        encoder: Option<DirectionalWireEncoder>,
        decoder: Option<EnvelopeDecoder>,
        timing: TransportTimingRecorder,
        metrics: AdapterIoMetrics,
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl<'socket> WebSocketYaoDuplexTransport<'socket> {
        fn new(
            socket: &'socket worker::WebSocket,
            events: worker::EventStream<'socket>,
            session: [u8; 32],
            timing: TransportTimingRecorder,
        ) -> Result<Self, AdapterError> {
            Ok(Self {
                socket,
                events,
                encoder: Some(DirectionalWireEncoder::new(
                    WireDirection::DeriverAToDeriverB,
                    session,
                )?),
                decoder: Some(EnvelopeDecoder::new(
                    WireDirection::DeriverBToDeriverA,
                    session,
                )?),
                timing,
                metrics: AdapterIoMetrics::default(),
            })
        }
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    impl YaoDuplexTransport for WebSocketYaoDuplexTransport<'_> {
        async fn send(
            &mut self,
            message: WireMessage,
        ) -> Result<Option<InboundTransportEvent>, AdapterError> {
            let message_kind = message.kind();
            send_websocket_envelope(
                self.socket,
                self.encoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                message,
                &mut self.metrics,
            )?;
            self.timing.mark(TimingEvent::AToBBodyByteEmitted)?;
            match message_kind {
                WireMessageKind::TableFrame => {
                    self.timing.mark(TimingEvent::TableFrameAccepted)?;
                }
                WireMessageKind::OutputTranslation => {
                    self.timing.mark(TimingEvent::TranslationAccepted)?;
                }
                _ => {}
            }
            Ok(None)
        }

        async fn receive(&mut self) -> Result<InboundTransportEvent, AdapterError> {
            match next_websocket_event(&mut self.events).await? {
                WebSocketTransportEvent::Binary(payload) => {
                    self.timing.mark(TimingEvent::BToABodyByteReceived)?;
                    let message = decode_websocket_envelope(
                        self.decoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                        payload,
                        &mut self.metrics,
                    )?;
                    Ok(InboundTransportEvent::Message(message))
                }
                WebSocketTransportEvent::Closed => {
                    let evidence = self
                        .decoder
                        .take()
                        .ok_or(AdapterError::ProtocolState)?
                        .finish()?;
                    Ok(InboundTransportEvent::Eof(evidence))
                }
            }
        }

        async fn close_local_direction(
            &mut self,
        ) -> Result<(DirectionalEofEvidence, Option<InboundTransportEvent>), AdapterError> {
            let evidence = self
                .encoder
                .take()
                .ok_or(AdapterError::ProtocolState)?
                .finish_after_transport_close()?;
            self.socket
                .send_with_bytes(WEBSOCKET_DIRECTION_EOF)
                .map_err(|_| AdapterError::WebSocketSend)?;
            self.timing.mark(TimingEvent::RequestDirectionClosed)?;
            Ok((evidence, None))
        }

        async fn finish(self) -> Result<YaoDuplexTransportCompletion, AdapterError> {
            if self.encoder.is_some() || self.decoder.is_some() {
                return Err(AdapterError::ProtocolState);
            }
            Ok(YaoDuplexTransportCompletion {
                io_metrics: self.metrics,
            })
        }
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    async fn run_deriver_a_websocket(
        env: &Env,
        deployment_id: DeploymentId,
        session: [u8; 32],
        deriver_a_colo: Option<Colo>,
        timeout_socket: Rc<RefCell<Option<worker::WebSocket>>>,
    ) -> Result<DeriverABenchmarkCompletion, AdapterError> {
        let timing = TransportTimingRecorder::worker()?;
        let protocol = websocket_protocol(&deployment_id, session);
        let socket = connect_deriver_b_websocket(env, &protocol).await?;
        *timeout_socket
            .try_borrow_mut()
            .map_err(|_| AdapterError::WebSocketConnect)? = Some(socket.clone());
        let negotiated_protocol = socket.as_ref().protocol();
        if !negotiated_protocol.is_empty() && negotiated_protocol != protocol {
            return Err(AdapterError::WebSocketProtocol);
        }
        socket
            .as_ref()
            .set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
        let events = socket
            .events()
            .map_err(|_| AdapterError::WebSocketConnect)?;
        socket
            .accept()
            .map_err(|_| AdapterError::WebSocketConnect)?;

        timing.mark(TimingEvent::BResponseHeadersReceived)?;
        let transport = WebSocketYaoDuplexTransport::new(&socket, events, session, timing.clone())?;
        run_deriver_a(
            transport,
            deployment_id,
            session,
            PlacementEvidence::new(deriver_a_colo, None),
            timing,
        )
        .await
    }

    #[cfg(feature = "deriver-a")]
    enum PeerCompletion {
        #[cfg(not(feature = "deriver-a-same-account-rpc"))]
        Fetch,
        #[cfg(feature = "deriver-a-same-account-rpc")]
        Rpc {
            method: oneshot::Receiver<Result<(), AdapterError>>,
            outbound: oneshot::Receiver<Result<(), AdapterError>>,
        },
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    async fn resolve_rpc_peer_completion(completion: JsFuture) -> Result<(), AdapterError> {
        let result = completion.await.map_err(|_| AdapterError::ServiceBinding)?;
        if result.as_string().as_deref() != Some("ok") {
            return Err(AdapterError::PeerStatus);
        }
        Ok(())
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    fn start_rpc_peer_completion(
        completion: worker::js_sys::Promise,
    ) -> oneshot::Receiver<Result<(), AdapterError>> {
        let (sender, receiver) = oneshot::channel();
        spawn_local(async move {
            let outcome = resolve_rpc_peer_completion(JsFuture::from(completion)).await;
            let _ = sender.send(outcome);
        });
        receiver
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    async fn pump_rpc_outbound(
        mut outbound: StreamBody<OutboundEnvelopeStream>,
        pipe: RpcIdentityBytePipe,
    ) -> Result<(), AdapterError> {
        while let Some(frame) = outbound.next().await {
            let frame = frame?;
            let bytes = frame.into_data().map_err(|_| AdapterError::OutboundBody)?;
            let write = pipe
                .write(bytes.as_ref())
                .map_err(|_| AdapterError::OutboundBody)?;
            JsFuture::from(write)
                .await
                .map_err(|_| AdapterError::OutboundBody)?;
        }
        let close = pipe.close().map_err(|_| AdapterError::OutboundEof)?;
        JsFuture::from(close)
            .await
            .map_err(|_| AdapterError::OutboundEof)?;
        Ok(())
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    async fn resolve_rpc_outbound(
        outbound: StreamBody<OutboundEnvelopeStream>,
        pipe: RpcIdentityBytePipe,
    ) -> Result<(), AdapterError> {
        let outcome = pump_rpc_outbound(outbound, pipe.clone()).await;
        if let Err(error) = outcome {
            if let Ok(abort) = pipe.abort(error.code()) {
                let _ = JsFuture::from(abort).await;
            }
        }
        outcome
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    fn start_rpc_outbound(
        outbound: StreamBody<OutboundEnvelopeStream>,
        pipe: RpcIdentityBytePipe,
    ) -> oneshot::Receiver<Result<(), AdapterError>> {
        let (sender, receiver) = oneshot::channel();
        spawn_local(async move {
            let outcome = resolve_rpc_outbound(outbound, pipe).await;
            let _ = sender.send(outcome);
        });
        receiver
    }

    #[cfg(feature = "deriver-a")]
    impl PeerCompletion {
        async fn finish(self) -> Result<(), AdapterError> {
            match self {
                #[cfg(not(feature = "deriver-a-same-account-rpc"))]
                Self::Fetch => Ok(()),
                #[cfg(feature = "deriver-a-same-account-rpc")]
                Self::Rpc { method, outbound } => {
                    outbound.await.map_err(|_| AdapterError::OutboundEof)??;
                    method.await.map_err(|_| AdapterError::ServiceBinding)?
                }
            }
        }
    }

    #[cfg(feature = "deriver-a")]
    struct DeriverBPeerResponse {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: SecretIncomingBody,
        completion: PeerCompletion,
    }

    #[cfg(feature = "deriver-a")]
    impl DeriverBPeerResponse {
        #[cfg(not(feature = "deriver-a-same-account-rpc"))]
        fn from_raw(response: worker::web_sys::Response) -> Result<Self, AdapterError> {
            let body = response.body().ok_or(AdapterError::InboundBody)?;
            let body = SecretIncomingBody::new(body)?;
            let status = http::StatusCode::from_u16(response.status())
                .map_err(|_| AdapterError::PeerStatus)?;
            let headers = header_map_from_web_headers(response.headers())?;
            Ok(Self {
                status,
                headers,
                body,
                completion: PeerCompletion::Fetch,
            })
        }
    }

    #[cfg(any(
        all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")),
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(super) fn header_map_from_web_headers(
        headers: worker::web_sys::Headers,
    ) -> Result<http::HeaderMap, AdapterError> {
        let mut output = http::HeaderMap::new();
        for entry in headers.entries().into_iter() {
            let pair = entry
                .map_err(|_| AdapterError::Envelope)?
                .dyn_into::<worker::js_sys::Array>()
                .map_err(|_| AdapterError::Envelope)?;
            if pair.length() != 2 {
                return Err(AdapterError::Envelope);
            }
            let name = pair.get(0).as_string().ok_or(AdapterError::Envelope)?;
            let value = pair.get(1).as_string().ok_or(AdapterError::Envelope)?;
            let name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| AdapterError::Envelope)?;
            let value = http::HeaderValue::from_str(&value).map_err(|_| AdapterError::Envelope)?;
            output.append(name, value);
        }
        Ok(output)
    }

    #[cfg(feature = "deriver-a")]
    fn deriver_b_request_url(_env: &Env) -> Result<String, AdapterError> {
        Ok(DERIVER_B_URL.to_owned())
    }

    #[cfg(all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")))]
    async fn fetch_deriver_b(
        env: &Env,
        request: http::Request<StreamBody<OutboundEnvelopeStream>>,
        _abort_signal: &worker::AbortSignal,
    ) -> Result<DeriverBPeerResponse, AdapterError> {
        let request = worker::request_to_wasm(request).map_err(|_| AdapterError::ServiceBinding)?;
        let promise = service_binding(env)?
            .fetch(&request)
            .map_err(|_| AdapterError::ServiceBinding)?;
        let response = worker::js_sys::futures::JsFuture::from(promise)
            .await
            .map_err(|_| AdapterError::ServiceBinding)?
            .dyn_into::<worker::web_sys::Response>()
            .map_err(|_| AdapterError::ServiceBinding)?;
        DeriverBPeerResponse::from_raw(response)
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    async fn fetch_deriver_b(
        env: &Env,
        request: http::Request<StreamBody<OutboundEnvelopeStream>>,
        _abort_signal: &worker::AbortSignal,
    ) -> Result<DeriverBPeerResponse, AdapterError> {
        let deployment_id = request
            .headers()
            .get(DEPLOYMENT_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(AdapterError::DeploymentIdentity)?
            .to_owned();
        let session = request
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(AdapterError::Envelope)?
            .to_owned();
        let deriver_a_colo = request
            .headers()
            .get(DERIVER_A_COLO_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL);
        let outbound = request.into_body();
        let a_to_b = create_rpc_identity_byte_pipe();
        let a_to_b_readable = a_to_b.readable();
        let b_to_a = create_rpc_identity_byte_pipe();
        let completion = rpc_binding(env)?
            .run_ceremony(
                a_to_b_readable,
                b_to_a.writable(),
                &deployment_id,
                &session,
                deriver_a_colo,
            )
            .map_err(|_| AdapterError::ServiceBinding)?;
        let outbound = start_rpc_outbound(outbound, a_to_b);

        let mut headers = http::HeaderMap::new();
        headers.insert(
            DEPLOYMENT_ID_HEADER,
            http::HeaderValue::from_str(&deployment_id)
                .map_err(|_| AdapterError::DeploymentIdentity)?,
        );
        Ok(DeriverBPeerResponse {
            status: http::StatusCode::OK,
            headers,
            body: SecretIncomingBody::new(b_to_a.readable())?,
            completion: PeerCompletion::Rpc {
                method: start_rpc_peer_completion(completion),
                outbound,
            },
        })
    }

    #[cfg(feature = "deriver-a")]
    struct HttpYaoDuplexTransport {
        sender: Option<mpsc::Sender<WireMessage>>,
        eof_receiver: Option<oneshot::Receiver<Result<OutboundDirectionClose, AdapterError>>>,
        inbound: InboundEnvelopeBody,
        peer_completion: Option<PeerCompletion>,
        outbound_metrics: Option<AdapterIoMetrics>,
    }

    #[cfg(feature = "deriver-a")]
    impl YaoDuplexTransport for HttpYaoDuplexTransport {
        async fn send(
            &mut self,
            message: WireMessage,
        ) -> Result<Option<InboundTransportEvent>, AdapterError> {
            send_while_polling_peer(
                self.sender.as_mut().ok_or(AdapterError::ProtocolState)?,
                message,
                &mut self.inbound,
            )
            .await
        }

        async fn receive(&mut self) -> Result<InboundTransportEvent, AdapterError> {
            self.inbound.next_event().await
        }

        async fn close_local_direction(
            &mut self,
        ) -> Result<(DirectionalEofEvidence, Option<InboundTransportEvent>), AdapterError> {
            let (closed, event) = close_while_polling_peer(
                self.sender.take().ok_or(AdapterError::ProtocolState)?,
                self.eof_receiver
                    .take()
                    .ok_or(AdapterError::ProtocolState)?,
                &mut self.inbound,
            )
            .await?;
            self.outbound_metrics = Some(closed.metrics);
            Ok((closed.evidence, event))
        }

        async fn finish(mut self) -> Result<YaoDuplexTransportCompletion, AdapterError> {
            self.peer_completion
                .take()
                .ok_or(AdapterError::ProtocolState)?
                .finish()
                .await?;
            let io_metrics = self
                .inbound
                .metrics()
                .merge(self.outbound_metrics.ok_or(AdapterError::ProtocolState)?)?;
            Ok(YaoDuplexTransportCompletion { io_metrics })
        }
    }

    #[cfg(feature = "deriver-a")]
    async fn run_deriver_a_http(
        env: &Env,
        deployment_id: DeploymentId,
        session: [u8; 32],
        abort_signal: worker::AbortSignal,
        deriver_a_colo: Option<Colo>,
    ) -> Result<DeriverABenchmarkCompletion, AdapterError> {
        let timing = TransportTimingRecorder::worker()?;
        // futures-channel adds one guaranteed slot per sender, so a zero buffer
        // gives this single-sender stream exactly one queued envelope.
        let (sender, receiver) = mpsc::channel(0);
        let (eof_sender, eof_receiver) = oneshot::channel();
        let outbound = OutboundEnvelopeStream::new(session, receiver, eof_sender, timing.clone())?;
        let deriver_b_url = deriver_b_request_url(env)?;
        let mut request_builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(deriver_b_url)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(http::header::CACHE_CONTROL, "no-store")
            .header(SESSION_HEADER, encode_session(session))
            .header(DEPLOYMENT_ID_HEADER, deployment_id.header_value()?);
        if let Some(colo) = deriver_a_colo.as_ref() {
            request_builder = request_builder.header(DERIVER_A_COLO_HEADER, colo.header_value()?);
        }
        let mut request = request_builder
            .body(StreamBody::new(outbound))
            .map_err(|_| AdapterError::OutboundBody)?;
        request.extensions_mut().insert(abort_signal.clone());
        let response = fetch_deriver_b(env, request, &abort_signal).await?;
        timing.mark(TimingEvent::BResponseHeadersReceived)?;
        validate_deriver_b_response_identity(response.status, &response.headers, &deployment_id)?;
        let deriver_b_colo = optional_colo_header(&response.headers, DERIVER_B_COLO_HEADER)?;
        let transport = HttpYaoDuplexTransport {
            sender: Some(sender),
            eof_receiver: Some(eof_receiver),
            inbound: InboundEnvelopeBody::new(response.body, session, timing.clone())?,
            peer_completion: Some(response.completion),
            outbound_metrics: None,
        };
        run_deriver_a(
            transport,
            deployment_id,
            session,
            PlacementEvidence::new(deriver_a_colo, deriver_b_colo),
            timing,
        )
        .await
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    async fn run_deriver_a<T: YaoDuplexTransport>(
        mut transport: T,
        deployment_id: DeploymentId,
        session: [u8; 32],
        placement: PlacementEvidence,
        timing: TransportTimingRecorder,
    ) -> Result<DeriverABenchmarkCompletion, AdapterError> {
        let mut role = Activation128KiBDeriverA::new(session)?;
        let mut deferred = VecDeque::with_capacity(1);

        loop {
            match role.instruction()? {
                RelayInstruction::Advance => match advance_a(role, RelayEvent::Advance)? {
                    AProgress::Continue(next) => role = next,
                    AProgress::Send {
                        role: next,
                        message,
                    } => {
                        if let Some(event) = transport.send(message).await? {
                            push_deferred_transport_event(&mut deferred, event)?;
                        }
                        role = next;
                    }
                    AProgress::Complete(_) => return Err(AdapterError::ProtocolState),
                },
                RelayInstruction::Receive {
                    kind,
                    payload_bytes,
                } => {
                    let event = next_a_transport_event(&mut deferred, &mut transport).await?;
                    let InboundTransportEvent::Message(message) = event else {
                        return Err(AdapterError::ProtocolState);
                    };
                    validate_inbound_message(&message, kind, payload_bytes)?;
                    mark_deriver_a_receive_timing(&timing, kind)?;
                    role = accept_a_continue(advance_a(role, RelayEvent::Inbound(message))?)?;
                }
                RelayInstruction::CloseLocalDirection { terminal_kind } => {
                    if terminal_kind != WireMessageKind::OutputTranslation {
                        return Err(AdapterError::ProtocolState);
                    }
                    let (evidence, event) = transport.close_local_direction().await?;
                    if let Some(event) = event {
                        push_deferred_transport_event(&mut deferred, event)?;
                    }
                    role = accept_a_continue(advance_a(
                        role,
                        RelayEvent::LocalDirectionalEof(evidence),
                    )?)?;
                }
                RelayInstruction::ObservePeerEof { terminal_kind } => {
                    if terminal_kind != WireMessageKind::ReturnedOutputLabels {
                        return Err(AdapterError::ProtocolState);
                    }
                    let event = next_a_transport_event(&mut deferred, &mut transport).await?;
                    let InboundTransportEvent::Eof(evidence) = event else {
                        return Err(AdapterError::ProtocolState);
                    };
                    timing.mark(TimingEvent::ResponseEofComplete)?;
                    let AProgress::Complete(completion) =
                        advance_a(role, RelayEvent::InboundDirectionalEof(evidence))?
                    else {
                        return Err(AdapterError::ProtocolState);
                    };
                    let transport_completion = transport.finish().await?;
                    validate_deriver_a_wire_bytes(&completion, transport_completion.io_metrics)?;
                    return Ok(DeriverABenchmarkCompletion {
                        completion,
                        deployment_id,
                        io_metrics: transport_completion.io_metrics,
                        placement,
                        timings: timing.finish()?,
                    });
                }
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) async fn run_deriver_a_with_timeout(
        env: &Env,
        deployment_id: DeploymentId,
        session: [u8; 32],
        deriver_a_colo: Option<Colo>,
    ) -> Result<DeriverABenchmarkCompletion, AdapterError> {
        #[cfg(feature = "deriver-a")]
        let controller = worker::AbortController::default();
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        let timeout_socket = Rc::new(RefCell::new(None));
        #[cfg(feature = "deriver-a")]
        let ceremony = Box::pin(run_deriver_a_http(
            env,
            deployment_id,
            session,
            controller.signal(),
            deriver_a_colo,
        ));
        #[cfg(any(
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        let ceremony = Box::pin(run_deriver_a_websocket(
            env,
            deployment_id,
            session,
            deriver_a_colo,
            timeout_socket.clone(),
        ));
        let timeout = Box::pin(worker::Delay::from(CEREMONY_TIMEOUT));
        match select(ceremony, timeout).await {
            FutureEither::Left((result, _timeout)) => {
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                if let Ok(mut socket) = timeout_socket.try_borrow_mut() {
                    if result.is_err() {
                        if let Some(socket) = socket.as_ref() {
                            let _ignored = socket.close(Some(1011), Some("ceremony failed"));
                        }
                    }
                    socket.take();
                }
                result
            }
            FutureEither::Right(((), _ceremony)) => {
                #[cfg(feature = "deriver-a")]
                controller.abort();
                #[cfg(any(
                    feature = "deriver-a-cross-account",
                    feature = "deriver-a-same-account-websocket"
                ))]
                if let Ok(mut socket) = timeout_socket.try_borrow_mut() {
                    if let Some(socket) = socket.take() {
                        let _ignored = socket.close(Some(1011), Some("ceremony timeout"));
                    }
                }
                Err(AdapterError::Timeout)
            }
        }
    }

    #[cfg(all(feature = "deriver-a", not(feature = "deriver-a-same-account-rpc")))]
    fn service_binding(env: &Env) -> Result<worker_sys::Fetcher, AdapterError> {
        env.service(DERIVER_B_BINDING)
            .map(worker::Fetcher::into_rpc::<worker_sys::Fetcher>)
            .map_err(|_| AdapterError::ServiceBinding)
    }

    #[cfg(feature = "deriver-a-same-account-rpc")]
    fn rpc_binding(env: &Env) -> Result<DeriverBRpc, AdapterError> {
        env.service(DERIVER_B_BINDING)
            .map(worker::Fetcher::into_rpc::<DeriverBRpc>)
            .map_err(|_| AdapterError::ServiceBinding)
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) fn random_session() -> Result<[u8; 32], AdapterError> {
        loop {
            let mut session = [0_u8; 32];
            getrandom::getrandom(&mut session).map_err(|_| AdapterError::Randomness)?;
            if session.iter().any(|byte| *byte != 0) {
                return Ok(session);
            }
        }
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket"
    ))]
    pub(super) async fn require_empty_public_request_body(
        body: &mut Body,
    ) -> Result<(), AdapterError> {
        while let Some(fragment) = body.next().await {
            match fragment {
                Ok(fragment) if fragment.is_empty() => {}
                Ok(_) => return Err(AdapterError::PublicRequestBodyNonEmpty),
                Err(_) => return Err(AdapterError::PublicRequestBodyUnreadable),
            }
        }
        Ok(())
    }

    #[cfg(any(
        feature = "deriver-a",
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) fn encode_session(session: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in session {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) fn decode_session(encoded: &str) -> Result<[u8; 32], AdapterError> {
        if encoded.len() != 64 {
            return Err(AdapterError::Envelope);
        }
        let bytes = encoded.as_bytes();
        let mut session = [0_u8; 32];
        for (index, output) in session.iter_mut().enumerate() {
            let high = decode_nibble(bytes[index * 2])?;
            let low = decode_nibble(bytes[index * 2 + 1])?;
            *output = (high << 4) | low;
        }
        if session.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::Envelope);
        }
        Ok(session)
    }

    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    fn decode_nibble(byte: u8) -> Result<u8, AdapterError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(AdapterError::Envelope),
        }
    }

    // Keeping the role continuation inline avoids allocating per table frame.
    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    #[allow(clippy::large_enum_variant)]
    enum BProgress {
        Continue(Activation128KiBDeriverB),
        Send {
            role: Activation128KiBDeriverB,
            message: WireMessage,
        },
        Complete(ActivationDeriverBCompletion),
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    fn advance_b(
        role: Activation128KiBDeriverB,
        event: RelayEvent,
    ) -> Result<BProgress, AdapterError> {
        Ok(match role.handle(event)? {
            RelayStep::Continue(role) => BProgress::Continue(role),
            RelayStep::Send { role, message } => BProgress::Send { role, message },
            RelayStep::Complete(completion) => BProgress::Complete(completion),
        })
    }

    #[cfg(any(
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    fn continue_deriver_b_websocket(
        socket: &worker::WebSocket,
        encoder: &mut DirectionalWireEncoder,
        metrics: &mut AdapterIoMetrics,
        progress: BProgress,
    ) -> Result<Activation128KiBDeriverB, AdapterError> {
        match progress {
            BProgress::Continue(role) => Ok(role),
            BProgress::Send { role, message } => {
                send_websocket_envelope(socket, encoder, message, metrics)?;
                Ok(role)
            }
            BProgress::Complete(_) => Err(AdapterError::ProtocolState),
        }
    }

    #[cfg(any(
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(super) async fn run_deriver_b_websocket(
        socket: worker::WebSocket,
        deployment_id: DeploymentId,
        session: [u8; 32],
        placement: PlacementEvidence,
    ) -> Result<(), AdapterError> {
        socket
            .as_ref()
            .set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
        let mut events = socket
            .events()
            .map_err(|_| AdapterError::WebSocketConnect)?;
        socket
            .accept()
            .map_err(|_| AdapterError::WebSocketConnect)?;
        let mut role = Activation128KiBDeriverB::new(role_session(session))?;
        let mut decoder = Some(EnvelopeDecoder::new(
            WireDirection::DeriverAToDeriverB,
            session,
        )?);
        let mut encoder = Some(DirectionalWireEncoder::new(
            WireDirection::DeriverBToDeriverA,
            session,
        )?);
        let mut metrics = AdapterIoMetrics::default();

        loop {
            match role.instruction()? {
                RelayInstruction::Advance => {
                    role = continue_deriver_b_websocket(
                        &socket,
                        encoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                        &mut metrics,
                        advance_b(role, RelayEvent::Advance)?,
                    )?;
                }
                RelayInstruction::Receive {
                    kind,
                    payload_bytes,
                } => {
                    let WebSocketTransportEvent::Binary(payload) =
                        next_websocket_event(&mut events).await?
                    else {
                        return Err(AdapterError::ProtocolState);
                    };
                    let message = decode_websocket_envelope(
                        decoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                        payload,
                        &mut metrics,
                    )?;
                    validate_inbound_message(&message, kind, payload_bytes)?;
                    role = continue_deriver_b_websocket(
                        &socket,
                        encoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                        &mut metrics,
                        advance_b(role, RelayEvent::Inbound(message))?,
                    )?;
                }
                RelayInstruction::ObservePeerEof { terminal_kind } => {
                    if terminal_kind != WireMessageKind::OutputTranslation {
                        return Err(AdapterError::ProtocolState);
                    }
                    let WebSocketTransportEvent::Binary(payload) =
                        next_websocket_event(&mut events).await?
                    else {
                        return Err(AdapterError::ProtocolState);
                    };
                    if payload.as_ref() != WEBSOCKET_DIRECTION_EOF {
                        return Err(AdapterError::ProtocolState);
                    }
                    let evidence = decoder
                        .take()
                        .ok_or(AdapterError::ProtocolState)?
                        .finish()?;
                    role = continue_deriver_b_websocket(
                        &socket,
                        encoder.as_mut().ok_or(AdapterError::ProtocolState)?,
                        &mut metrics,
                        advance_b(role, RelayEvent::InboundDirectionalEof(evidence))?,
                    )?;
                }
                RelayInstruction::CloseLocalDirection { terminal_kind } => {
                    if terminal_kind != WireMessageKind::ReturnedOutputLabels {
                        return Err(AdapterError::ProtocolState);
                    }
                    let evidence = encoder
                        .take()
                        .ok_or(AdapterError::ProtocolState)?
                        .finish_after_transport_close()?;
                    let BProgress::Complete(completion) =
                        advance_b(role, RelayEvent::LocalDirectionalEof(evidence))?
                    else {
                        return Err(AdapterError::ProtocolState);
                    };
                    validate_deriver_b_wire_bytes(&completion, metrics)?;
                    log_b_completion(&completion, &deployment_id, metrics, &placement);
                    socket
                        .close(Some(1000), Some("complete"))
                        .map_err(|_| AdapterError::WebSocketSend)?;
                    return Ok(());
                }
            }
        }
    }

    #[cfg(all(
        any(
            feature = "deriver-b",
            feature = "deriver-b-cross-account",
            feature = "deriver-b-same-account-websocket",
            test
        ),
        feature = "fault-session-mismatch"
    ))]
    fn role_session(mut framing_session: [u8; 32]) -> [u8; 32] {
        framing_session[0] ^= 0x80;
        if framing_session.iter().all(|byte| *byte == 0) {
            framing_session[1] = 1;
        }
        framing_session
    }

    #[cfg(all(
        any(
            feature = "deriver-b",
            feature = "deriver-b-cross-account",
            feature = "deriver-b-same-account-websocket",
            test
        ),
        not(feature = "fault-session-mismatch")
    ))]
    const fn role_session(framing_session: [u8; 32]) -> [u8; 32] {
        framing_session
    }

    #[cfg(feature = "fault-wrong-role-offer-tag")]
    fn inject_wrong_role_offer_tag(
        mut envelope: Vec<u8>,
        message_kind: WireMessageKind,
    ) -> Vec<u8> {
        const BASE_OT_CHOICES_TAG: u8 = 2;
        if message_kind == WireMessageKind::BaseOtOffer {
            envelope[9] = BASE_OT_CHOICES_TAG;
        }
        envelope
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) struct DeriverBResponseStream {
        role: Option<Activation128KiBDeriverB>,
        deployment_id: DeploymentId,
        placement: PlacementEvidence,
        inbound: SecretIncomingBody,
        decoder: Option<EnvelopeDecoder>,
        encoder: Option<DirectionalWireEncoder>,
        fragment: Option<Bytes>,
        fragment_offset: usize,
        metrics: AdapterIoMetrics,
        #[cfg(feature = "fault-fragmentation")]
        pending_fragments: Option<DeterministicFragments>,
        #[cfg(feature = "fault-response-disconnect-after-offer")]
        disconnect_after_offer: bool,
        #[cfg(feature = "fault-stall-after-offer")]
        stall_after_offer: bool,
        #[cfg(feature = "fault-stall-after-offer")]
        stall_delay: Pin<Box<worker::Delay>>,
        terminated: bool,
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    impl DeriverBResponseStream {
        pub(super) fn new(
            deployment_id: DeploymentId,
            session: [u8; 32],
            inbound: SecretIncomingBody,
            placement: PlacementEvidence,
        ) -> Result<Self, AdapterError> {
            Ok(Self {
                role: Some(Activation128KiBDeriverB::new(role_session(session))?),
                deployment_id,
                placement,
                inbound,
                decoder: Some(EnvelopeDecoder::new(
                    WireDirection::DeriverAToDeriverB,
                    session,
                )?),
                encoder: Some(DirectionalWireEncoder::new(
                    WireDirection::DeriverBToDeriverA,
                    session,
                )?),
                fragment: None,
                fragment_offset: 0,
                metrics: AdapterIoMetrics::default(),
                #[cfg(feature = "fault-fragmentation")]
                pending_fragments: None,
                #[cfg(feature = "fault-response-disconnect-after-offer")]
                disconnect_after_offer: false,
                #[cfg(feature = "fault-stall-after-offer")]
                stall_after_offer: false,
                #[cfg(feature = "fault-stall-after-offer")]
                stall_delay: Box::pin(worker::Delay::from(std::time::Duration::from_secs(60))),
                terminated: false,
            })
        }

        fn fail(
            &mut self,
            error: AdapterError,
        ) -> Poll<Option<Result<Frame<Bytes>, AdapterError>>> {
            log_b_failure(error);
            self.role.take();
            self.decoder.take();
            self.encoder.take();
            self.fragment.take();
            self.terminated = true;
            Poll::Ready(Some(Err(error)))
        }

        fn apply(&mut self, event: RelayEvent) -> Result<BProgress, AdapterError> {
            let role = self.role.take().ok_or(AdapterError::ProtocolState)?;
            advance_b(role, event)
        }

        fn keep(&mut self, progress: BProgress) -> Result<Option<WireMessage>, AdapterError> {
            match progress {
                BProgress::Continue(role) => {
                    self.role = Some(role);
                    Ok(None)
                }
                BProgress::Send { role, message } => {
                    self.role = Some(role);
                    Ok(Some(message))
                }
                BProgress::Complete(_) => Err(AdapterError::ProtocolState),
            }
        }

        fn encode_response(&mut self, message: WireMessage) -> Result<Frame<Bytes>, AdapterError> {
            let encoder = self.encoder.as_mut().ok_or(AdapterError::ProtocolState)?;
            #[cfg(any(
                feature = "fault-response-disconnect-after-offer",
                feature = "fault-stall-after-offer",
                feature = "fault-wrong-role-offer-tag"
            ))]
            let message_kind = message.kind();
            let envelope = encoder
                .encode(message)
                .map_err(|_| AdapterError::OutboundBody)?;
            self.metrics.record_outgoing_envelope(envelope.len())?;
            #[cfg(feature = "fault-response-disconnect-after-offer")]
            if message_kind == WireMessageKind::BaseOtOffer {
                self.disconnect_after_offer = true;
            }
            #[cfg(feature = "fault-stall-after-offer")]
            if message_kind == WireMessageKind::BaseOtOffer {
                self.stall_after_offer = true;
            }
            #[cfg(feature = "fault-wrong-role-offer-tag")]
            let envelope = inject_wrong_role_offer_tag(envelope, message_kind);
            let envelope = Bytes::from_owner(Zeroizing::new(envelope));
            #[cfg(feature = "fault-fragmentation")]
            {
                let mut fragments = DeterministicFragments::new(envelope);
                let fragment = fragments
                    .next()
                    .expect("encoded envelopes are always non-empty");
                self.metrics
                    .record_injected_outgoing_fragment(fragment.len())?;
                self.pending_fragments = Some(fragments);
                Ok(Frame::data(fragment))
            }
            #[cfg(not(feature = "fault-fragmentation"))]
            Ok(Frame::data(envelope))
        }

        fn complete_body(&mut self) -> Result<(), AdapterError> {
            let encoder = self.encoder.take().ok_or(AdapterError::ProtocolState)?;
            let evidence = encoder.finish_after_transport_close()?;
            let progress = self.apply(RelayEvent::LocalDirectionalEof(evidence))?;
            let BProgress::Complete(completion) = progress else {
                return Err(AdapterError::ProtocolState);
            };
            validate_deriver_b_wire_bytes(&completion, self.metrics)?;
            log_b_completion(
                &completion,
                &self.deployment_id,
                self.metrics,
                &self.placement,
            );
            self.terminated = true;
            Ok(())
        }

        fn push_current_fragment(&mut self) -> Result<bool, AdapterError> {
            let Some(fragment) = self.fragment.as_ref() else {
                return Ok(false);
            };
            let decoder = self.decoder.as_mut().ok_or(AdapterError::ProtocolState)?;
            let consumed = decoder.push_once(&fragment[self.fragment_offset..])?;
            self.fragment_offset += consumed;
            if self.fragment_offset == fragment.len() {
                self.fragment = None;
                self.fragment_offset = 0;
            }
            Ok(true)
        }

        fn retain_fragment(&mut self, fragment: Bytes) -> Result<(), AdapterError> {
            self.metrics.record_incoming_fragment(fragment.len())?;
            self.fragment = Some(fragment);
            self.fragment_offset = 0;
            Ok(())
        }
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    fn log_b_completion(
        completion: &ActivationDeriverBCompletion,
        deployment_id: &DeploymentId,
        io_metrics: AdapterIoMetrics,
        placement: &PlacementEvidence,
    ) {
        let metrics = completion.stream_metrics();
        let wire = completion.wire_byte_ledger();
        let mut report = serde_json::json!({
            "event": "ed25519_yao_benchmark_b_complete",
            "benchmark": "phase9b-cloudflare-activation-128kib",
            "benchmark_only": true,
            "role": "deriver-b",
            "topology": B_TOPOLOGY_LABEL,
            "family": "activation",
            "profile": "128KiB",
            "workers_rs_version": WORKERS_RS_VERSION,
            "deriver_a_colo": placement.deriver_a_colo().map(Colo::as_str),
            "deriver_b_colo": placement.deriver_b_colo().map(Colo::as_str),
            "table_payload_bytes": metrics.table_payload_bytes(),
            "body_bytes": metrics.body_bytes(),
            "frame_count": metrics.frame_count(),
            "peak_table_buffer_bytes": metrics.combined_peak_table_buffer_bytes(),
            "total_incoming_body_bytes": io_metrics.total_incoming_body_bytes(),
            "max_incoming_platform_fragment_bytes": io_metrics.max_incoming_platform_fragment_bytes(),
            "total_outgoing_envelope_bytes": io_metrics.total_outgoing_envelope_bytes(),
            "peak_outgoing_envelope_bytes": io_metrics.peak_outgoing_envelope_bytes(),
            "workers_rs_outgoing_stream_body_copy_passes": WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES,
            "workers_rs_outgoing_stream_body_copy_bytes": io_metrics.workers_rs_outgoing_stream_body_copy_bytes(),
            "injected_outgoing_fragment_count": io_metrics.injected_outgoing_fragment_count(),
            "max_injected_outgoing_fragment_bytes": io_metrics.max_injected_outgoing_fragment_bytes(),
            "max_queued_outgoing_envelopes": MAX_QUEUED_OUTGOING_ENVELOPES,
        });
        add_deployment_id_field(&mut report, deployment_id);
        add_secret_ingress_copy_fields(&mut report, io_metrics);
        add_wire_fields(&mut report, wire);
        add_nonpromotion_fields(&mut report);
        worker::console_log!("{}", report);
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    pub(super) fn log_b_failure(error: AdapterError) {
        #[cfg(target_arch = "wasm32")]
        worker::console_error!(
            "{{\"event\":\"ed25519_yao_benchmark_b_failed\",\"benchmark_only\":true,\"role\":\"deriver-b\",\"topology\":\"{}\",\"error_code\":\"{}\"}}",
            B_TOPOLOGY_LABEL,
            error.code(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        let _ignored = error;
    }

    #[cfg(any(
        feature = "deriver-b",
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket",
        test
    ))]
    impl Stream for DeriverBResponseStream {
        type Item = Result<Frame<Bytes>, AdapterError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.terminated {
                return Poll::Ready(None);
            }
            #[cfg(feature = "fault-fragmentation")]
            if let Some(fragments) = self.pending_fragments.as_mut() {
                if let Some(fragment) = fragments.next() {
                    if self
                        .metrics
                        .record_injected_outgoing_fragment(fragment.len())
                        .is_err()
                    {
                        return self.fail(AdapterError::MeasurementOverflow);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(fragment))));
                }
                self.pending_fragments = None;
            }
            #[cfg(feature = "fault-response-disconnect-after-offer")]
            if self.disconnect_after_offer {
                return self.fail(AdapterError::InjectedResponseDisconnect);
            }
            #[cfg(feature = "fault-stall-after-offer")]
            if self.stall_after_offer {
                return match std::future::Future::poll(self.stall_delay.as_mut(), cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => self.fail(AdapterError::ProtocolState),
                };
            }
            loop {
                let instruction = match self.role.as_ref() {
                    Some(role) => match role.instruction() {
                        Ok(instruction) => instruction,
                        Err(_) => return self.fail(AdapterError::Role),
                    },
                    None => return self.fail(AdapterError::ProtocolState),
                };
                match instruction {
                    RelayInstruction::Advance => {
                        let progress = match self.apply(RelayEvent::Advance) {
                            Ok(progress) => progress,
                            Err(error) => return self.fail(error),
                        };
                        match self.keep(progress) {
                            Ok(Some(message)) => match self.encode_response(message) {
                                Ok(frame) => return Poll::Ready(Some(Ok(frame))),
                                Err(error) => return self.fail(error),
                            },
                            Ok(None) => {}
                            Err(error) => return self.fail(error),
                        }
                    }
                    RelayInstruction::Receive {
                        kind,
                        payload_bytes,
                    } => {
                        let message = self.decoder.as_mut().and_then(EnvelopeDecoder::pop_message);
                        if let Some(message) = message {
                            if validate_inbound_message(&message, kind, payload_bytes).is_err() {
                                return self.fail(AdapterError::Envelope);
                            }
                            let progress = match self.apply(RelayEvent::Inbound(message)) {
                                Ok(progress) => progress,
                                Err(error) => return self.fail(error),
                            };
                            match self.keep(progress) {
                                Ok(Some(message)) => match self.encode_response(message) {
                                    Ok(frame) => return Poll::Ready(Some(Ok(frame))),
                                    Err(error) => return self.fail(error),
                                },
                                Ok(None) => {}
                                Err(error) => return self.fail(error),
                            }
                            continue;
                        }
                        match self.push_current_fragment() {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => return self.fail(error),
                        }
                        match Pin::new(&mut self.inbound).poll_next(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Some(Ok(fragment))) if fragment.is_empty() => {}
                            Poll::Ready(Some(Ok(fragment))) => {
                                if let Err(error) = self.retain_fragment(fragment) {
                                    return self.fail(error);
                                }
                            }
                            Poll::Ready(Some(Err(_))) => {
                                return self.fail(AdapterError::InboundBody)
                            }
                            Poll::Ready(None) => return self.fail(AdapterError::ProtocolState),
                        }
                    }
                    RelayInstruction::ObservePeerEof { terminal_kind } => {
                        if terminal_kind != WireMessageKind::OutputTranslation {
                            return self.fail(AdapterError::ProtocolState);
                        }
                        match self.push_current_fragment() {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => return self.fail(error),
                        }
                        match Pin::new(&mut self.inbound).poll_next(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Some(Ok(fragment))) if fragment.is_empty() => {}
                            Poll::Ready(Some(Ok(fragment))) => {
                                if let Err(error) = self.retain_fragment(fragment) {
                                    return self.fail(error);
                                }
                            }
                            Poll::Ready(Some(Err(_))) => {
                                return self.fail(AdapterError::InboundBody)
                            }
                            Poll::Ready(None) => {
                                let decoder = match self.decoder.take() {
                                    Some(decoder) => decoder,
                                    None => return self.fail(AdapterError::ProtocolState),
                                };
                                let evidence = match decoder.finish() {
                                    Ok(evidence) => evidence,
                                    Err(error) => return self.fail(error),
                                };
                                let progress =
                                    match self.apply(RelayEvent::InboundDirectionalEof(evidence)) {
                                        Ok(progress) => progress,
                                        Err(error) => return self.fail(error),
                                    };
                                if let Err(error) = self.keep(progress) {
                                    return self.fail(error);
                                }
                            }
                        }
                    }
                    RelayInstruction::CloseLocalDirection { terminal_kind } => {
                        if terminal_kind != WireMessageKind::ReturnedOutputLabels {
                            return self.fail(AdapterError::ProtocolState);
                        }
                        return match self.complete_body() {
                            #[cfg(feature = "fault-trailing-after-terminal")]
                            Ok(()) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                                b"YAOS_AB_FAULT_TRAILING_AFTER_TERMINAL",
                            ))))),
                            #[cfg(not(feature = "fault-trailing-after-terminal"))]
                            Ok(()) => Poll::Ready(None),
                            Err(error) => self.fail(error),
                        };
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::Cell;

        struct ManualClock {
            now_ms: Cell<f64>,
        }

        impl IoBoundaryClock for ManualClock {
            fn now_ms(&self) -> f64 {
                self.now_ms.get()
            }
        }

        fn manual_timing(started_ms: f64) -> (Rc<ManualClock>, TransportTimingRecorder) {
            let clock = Rc::new(ManualClock {
                now_ms: Cell::new(started_ms),
            });
            let timing = TransportTimingRecorder::new(clock.clone()).expect("timing recorder");
            (clock, timing)
        }

        fn fixture_deployment_id() -> DeploymentId {
            DeploymentId::parse("0123456789abcdef0123456789abcdef").expect("fixture deployment id")
        }

        fn first_a_messages(session: [u8; 32]) -> (WireMessage, WireMessage) {
            let b = Activation128KiBDeriverB::new(session).expect("B fixture role");
            let RelayStep::Send { message: offer, .. } =
                b.handle(RelayEvent::Advance).expect("offer")
            else {
                panic!("B must emit the offer first");
            };
            let a = Activation128KiBDeriverA::new(session).expect("A fixture role");
            let RelayStep::Continue(a) =
                a.handle(RelayEvent::Inbound(offer)).expect("accept offer")
            else {
                panic!("A must accept the offer");
            };
            let RelayStep::Send {
                role: a,
                message: base_choices,
            } = a.handle(RelayEvent::Advance).expect("base choices")
            else {
                panic!("A must emit base choices");
            };
            let RelayStep::Send {
                message: direct, ..
            } = a.handle(RelayEvent::Advance).expect("direct labels")
            else {
                panic!("A must emit direct labels");
            };
            (base_choices, direct)
        }

        #[cfg(not(feature = "fault-wrong-role-offer-tag"))]
        fn poll_b_message(stream: &mut DeriverBResponseStream, session: [u8; 32]) -> WireMessage {
            let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
            let mut decoder =
                EnvelopeDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("decoder");
            loop {
                let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut *stream).poll_next(&mut context)
                else {
                    panic!("B must emit a complete message");
                };
                let fragment = frame.into_data().expect("message data frame");
                let consumed = decoder.push_once(&fragment).expect("message fragment");
                assert_eq!(consumed, fragment.len());
                if let Some(message) = decoder.pop_message() {
                    return message;
                }
            }
        }

        #[test]
        fn session_header_is_strict_and_round_trips() {
            let session = [0xa5; 32];
            let encoded = encode_session(session);
            assert_eq!(decode_session(&encoded), Ok(session));
            assert!(decode_session(&encoded.to_uppercase()).is_err());
            assert!(decode_session(&"0".repeat(64)).is_err());
        }

        #[test]
        fn websocket_subprotocol_binds_exact_deployment_and_session() {
            let deployment_id = fixture_deployment_id();
            let session = [0xa5; 32];
            let protocol = websocket_protocol(&deployment_id, session);
            assert_eq!(
                parse_websocket_protocol(&protocol),
                Ok((deployment_id, session))
            );
            for rejected in [
                "yaos-ab-v1",
                "yaos-ab-v2.0123456789abcdef0123456789abcdef.a5",
                "yaos-ab-v1.0123456789abcdef0123456789abcdef.0000000000000000000000000000000000000000000000000000000000000000",
                "yaos-ab-v1.0123456789abcdef0123456789abcdef.a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5.extra",
            ] {
                assert!(
                    parse_websocket_protocol(rejected).is_err(),
                    "accepted invalid WebSocket subprotocol: {rejected}"
                );
            }
        }

        #[test]
        fn deployment_identity_boundary_accepts_only_exact_lowercase_hex() {
            let expected = fixture_deployment_id();
            assert_eq!(expected.as_str(), "0123456789abcdef0123456789abcdef");
            assert_eq!(
                expected.header_value().expect("header value"),
                http::HeaderValue::from_static("0123456789abcdef0123456789abcdef")
            );
            for rejected in [
                "",
                "0123456789abcdef0123456789abcde",
                "0123456789abcdef0123456789abcdef0",
                "0123456789ABCDEF0123456789ABCDEF",
                "g123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcde-",
                "00000000000000000000000000000000",
            ] {
                assert_eq!(
                    DeploymentId::parse(rejected),
                    Err(AdapterError::DeploymentIdentity),
                    "accepted invalid deployment id: {rejected}"
                );
            }
        }

        #[test]
        fn deployment_identity_header_is_required_unique_and_strict() {
            let mut headers = http::HeaderMap::new();
            assert_eq!(
                deployment_id_header(&headers),
                Err(AdapterError::DeploymentIdentity)
            );
            headers.insert(
                DEPLOYMENT_ID_HEADER,
                http::HeaderValue::from_static("0123456789abcdef0123456789abcdef"),
            );
            assert_eq!(deployment_id_header(&headers), Ok(fixture_deployment_id()));
            headers.append(
                DEPLOYMENT_ID_HEADER,
                http::HeaderValue::from_static("fedcba9876543210fedcba9876543210"),
            );
            assert_eq!(
                deployment_id_header(&headers),
                Err(AdapterError::DeploymentIdentity)
            );
        }

        #[test]
        fn peer_response_identity_must_match_before_protocol_streaming() {
            let expected = fixture_deployment_id();
            let mut matching = http::HeaderMap::new();
            matching.insert(
                DEPLOYMENT_ID_HEADER,
                http::HeaderValue::from_static("0123456789abcdef0123456789abcdef"),
            );
            assert_eq!(
                validate_deriver_b_response_identity(http::StatusCode::OK, &matching, &expected),
                Ok(())
            );

            let mut mismatched = http::HeaderMap::new();
            mismatched.insert(
                DEPLOYMENT_ID_HEADER,
                http::HeaderValue::from_static("fedcba9876543210fedcba9876543210"),
            );
            for headers in [&http::HeaderMap::new(), &mismatched] {
                assert_eq!(
                    validate_deriver_b_response_identity(http::StatusCode::OK, headers, &expected),
                    Err(AdapterError::DeploymentIdentity)
                );
            }
            assert_eq!(
                validate_deriver_b_response_identity(
                    http::StatusCode::PRECONDITION_FAILED,
                    &http::HeaderMap::new(),
                    &expected
                ),
                Err(AdapterError::DeploymentIdentity)
            );
            assert_eq!(
                validate_deriver_b_response_identity(
                    http::StatusCode::IM_A_TEAPOT,
                    &http::HeaderMap::new(),
                    &expected
                ),
                Err(AdapterError::PeerStatus)
            );
        }

        #[test]
        fn colo_boundary_accepts_exactly_three_uppercase_ascii_bytes() {
            assert_eq!(Colo::parse("NRT").expect("colo").as_str(), "NRT");
            for rejected in ["", "NR", "NRT1", "nrt", "NrT", "N1T", "N\u{00c4}T"] {
                assert_eq!(
                    Colo::parse(rejected),
                    Err(AdapterError::PlacementEvidence),
                    "accepted invalid colo: {rejected}"
                );
            }
        }

        #[test]
        fn colo_headers_are_optional_unique_and_strict() {
            let empty = http::HeaderMap::new();
            let nrt = Colo::parse("NRT").expect("fixture colo");
            assert_eq!(
                nrt.header_value().expect("header value"),
                http::HeaderValue::from_static("NRT")
            );
            assert_eq!(
                optional_colo_header(&empty, DERIVER_B_COLO_HEADER),
                Ok(None)
            );
            assert_eq!(
                optional_colo_header(&empty, DERIVER_A_COLO_HEADER),
                Ok(None)
            );

            let mut valid = http::HeaderMap::new();
            valid.insert(DERIVER_B_COLO_HEADER, http::HeaderValue::from_static("SJC"));
            assert_eq!(
                optional_colo_header(&valid, DERIVER_B_COLO_HEADER),
                Ok(Some(Colo::parse("SJC").expect("fixture colo")))
            );

            let mut duplicate = valid.clone();
            duplicate.append(DERIVER_B_COLO_HEADER, http::HeaderValue::from_static("LAX"));
            assert_eq!(
                optional_colo_header(&duplicate, DERIVER_B_COLO_HEADER),
                Err(AdapterError::PlacementEvidence)
            );

            let mut malformed = http::HeaderMap::new();
            malformed.insert(DERIVER_B_COLO_HEADER, http::HeaderValue::from_static("sjc"));
            assert_eq!(
                optional_colo_header(&malformed, DERIVER_B_COLO_HEADER),
                Err(AdapterError::PlacementEvidence)
            );
        }

        #[test]
        fn local_request_without_cloudflare_metadata_has_no_colo() {
            let request = http::Request::new(Body::empty());
            assert_eq!(incoming_colo(&request), Ok(None));
        }

        #[test]
        fn deterministic_clock_produces_ordered_transport_phase_durations() {
            let (clock, timing) = manual_timing(100.0);
            let events = [
                (105.0, TimingEvent::BResponseHeadersReceived),
                (106.0, TimingEvent::BToABodyByteReceived),
                (107.0, TimingEvent::OfferReceived),
                (108.0, TimingEvent::AToBBodyByteEmitted),
                (110.0, TimingEvent::ExtensionReceived),
                (112.0, TimingEvent::TableFrameAccepted),
                (130.0, TimingEvent::TableFrameAccepted),
                (132.0, TimingEvent::TranslationAccepted),
                (133.0, TimingEvent::AToBBodyByteEmitted),
                (134.0, TimingEvent::RequestDirectionClosed),
                (138.0, TimingEvent::BToABodyByteReceived),
                (139.0, TimingEvent::ReturnedReceived),
                (140.0, TimingEvent::ResponseEofComplete),
            ];
            for (now_ms, event) in events {
                clock.now_ms.set(now_ms);
                timing.mark(event).expect("ordered milestone");
            }
            let result = timing.finish().expect("complete timings");
            assert_eq!(result.b_response_headers_received_ms(), 5.0);
            assert_eq!(result.b_to_a_first_body_byte_received_ms(), 6.0);
            assert_eq!(result.offer_received_ms(), 7.0);
            assert_eq!(result.a_to_b_first_body_byte_emitted_ms(), 8.0);
            assert_eq!(result.extension_received_ms(), 10.0);
            assert_eq!(result.first_table_frame_accepted_ms(), 12.0);
            assert_eq!(result.last_table_frame_accepted_ms(), 30.0);
            assert_eq!(result.translation_accepted_ms(), 32.0);
            assert_eq!(result.a_to_b_final_body_byte_emitted_ms(), 33.0);
            assert_eq!(result.request_direction_closed_ms(), 34.0);
            assert_eq!(result.b_to_a_final_body_byte_received_ms(), 38.0);
            assert_eq!(result.returned_received_ms(), 39.0);
            assert_eq!(result.response_eof_complete_ms(), 40.0);
            assert_eq!(result.table_stream_duration_ms(), 18.0);
            assert_eq!(result.total_protocol_duration_ms(), 40.0);
        }

        #[test]
        fn timing_evidence_rejects_missing_duplicate_and_backward_milestones() {
            let (clock, timing) = manual_timing(10.0);
            assert_eq!(timing.finish(), Err(AdapterError::TimingEvidence));
            clock.now_ms.set(11.0);
            timing
                .mark(TimingEvent::BResponseHeadersReceived)
                .expect("first milestone");
            assert_eq!(
                timing.mark(TimingEvent::BResponseHeadersReceived),
                Err(AdapterError::TimingEvidence)
            );

            let (clock, timing) = manual_timing(20.0);
            clock.now_ms.set(19.0);
            assert_eq!(
                timing.mark(TimingEvent::OfferReceived),
                Err(AdapterError::TimingEvidence)
            );
        }

        #[test]
        fn envelope_decoder_accepts_arbitrary_single_byte_fragmentation() {
            let session = [0x5a; 32];
            let role = Activation128KiBDeriverB::new(session).expect("fixture role");
            let RelayStep::Send { message, .. } =
                role.handle(RelayEvent::Advance).expect("initial offer")
            else {
                panic!("B must emit the offer first");
            };
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session)
                    .expect("encoder");
            let envelope = encoder.encode(message).expect("offer envelope");
            let mut decoder =
                EnvelopeDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("decoder");
            for byte in &envelope {
                decoder
                    .push_once(std::slice::from_ref(byte))
                    .expect("fragment");
            }
            let message = decoder.pop_message().expect("decoded offer");
            assert_eq!(message.kind(), WireMessageKind::BaseOtOffer);
            assert!(decoder.pop_message().is_none());
        }

        #[test]
        fn coalesced_envelopes_are_exposed_one_at_a_time() {
            let session = [0x4c; 32];
            let (base_choices, direct) = first_a_messages(session);
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("encoder");
            let mut coalesced = encoder.encode(base_choices).expect("base choices envelope");
            coalesced.extend_from_slice(&encoder.encode(direct).expect("direct envelope"));

            let mut decoder =
                EnvelopeDecoder::new(WireDirection::DeriverAToDeriverB, session).expect("decoder");
            let first_consumed = decoder.push_once(&coalesced).expect("first envelope");
            assert!(first_consumed < coalesced.len());
            assert_eq!(
                decoder.pop_message().expect("first message").kind(),
                WireMessageKind::BaseOtChoices
            );
            let second_consumed = decoder
                .push_once(&coalesced[first_consumed..])
                .expect("second envelope");
            assert_eq!(first_consumed + second_consumed, coalesced.len());
            assert_eq!(
                decoder.pop_message().expect("second message").kind(),
                WireMessageKind::DirectInputLabels
            );
            assert!(decoder.pop_message().is_none());
        }

        #[test]
        fn mid_envelope_transport_eof_is_rejected() {
            let session = [0x2e; 32];
            let role = Activation128KiBDeriverB::new(session).expect("fixture role");
            let RelayStep::Send { message, .. } =
                role.handle(RelayEvent::Advance).expect("initial offer")
            else {
                panic!("B must emit the offer first");
            };
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session)
                    .expect("encoder");
            let envelope = encoder.encode(message).expect("offer envelope");
            let split = envelope.len() / 2;
            let mut decoder =
                EnvelopeDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("decoder");
            assert_eq!(
                decoder.push_once(&envelope[..split]).expect("prefix"),
                split
            );
            assert!(decoder.finish().is_err());
        }

        #[test]
        fn cross_account_endpoint_accepts_only_the_fixed_websocket_route() {
            let endpoint = CrossAccountWebSocketEndpoint::parse(
                "wss://deriver-b.example.com/benchmark/activation",
            )
            .expect("fixed endpoint");
            assert_eq!(
                endpoint.as_str(),
                "wss://deriver-b.example.com/benchmark/activation"
            );

            for rejected in [
                "https://deriver-b.example.com/benchmark/activation",
                "ws://deriver-b.example.com/benchmark/activation",
                "http://deriver-b.example.com/benchmark/activation",
                "wss://user@deriver-b.example.com/benchmark/activation",
                "wss://user:password@deriver-b.example.com/benchmark/activation",
                "wss://deriver-b.example.com:8443/benchmark/activation",
                "wss://deriver-b.example.com/benchmark/activation/",
                "wss://deriver-b.example.com/benchmark/export",
                "wss://deriver-b.example.com/benchmark/activation?profile=128",
                "wss://deriver-b.example.com/benchmark/activation#fragment",
                "/benchmark/activation",
            ] {
                assert!(
                    CrossAccountWebSocketEndpoint::parse(rejected).is_err(),
                    "accepted invalid endpoint: {rejected}"
                );
            }
        }

        #[cfg(not(feature = "fault-wrong-role-offer-tag"))]
        #[test]
        fn deriver_b_emits_offer_before_reading_an_empty_request_body() {
            let session = [0x7b; 32];
            let mut stream = DeriverBResponseStream::new(
                fixture_deployment_id(),
                session,
                SecretIncomingBody::empty(),
                PlacementEvidence::new(None, None),
            )
            .expect("B response stream");
            assert_eq!(
                poll_b_message(&mut stream, session).kind(),
                WireMessageKind::BaseOtOffer
            );
        }

        #[cfg(not(any(
            feature = "fault-response-disconnect-after-offer",
            feature = "fault-stall-after-offer",
            feature = "fault-wrong-role-offer-tag"
        )))]
        #[test]
        fn deriver_b_rejects_request_eof_before_base_choices() {
            let session = [0x6c; 32];
            let mut stream = DeriverBResponseStream::new(
                fixture_deployment_id(),
                session,
                SecretIncomingBody::empty(),
                PlacementEvidence::new(None, None),
            )
            .expect("B response stream");
            let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
            assert_eq!(
                poll_b_message(&mut stream, session).kind(),
                WireMessageKind::BaseOtOffer
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut context),
                Poll::Ready(Some(Err(AdapterError::ProtocolState)))
            ));
        }

        #[cfg(feature = "fault-stall-after-offer")]
        #[test]
        fn stall_fault_arms_only_after_emitting_the_offer() {
            let session = [0x71; 32];
            let mut stream = DeriverBResponseStream::new(
                fixture_deployment_id(),
                session,
                SecretIncomingBody::empty(),
                PlacementEvidence::new(None, None),
            )
            .expect("B response stream");
            let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
            assert!(!stream.stall_after_offer);
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut context),
                Poll::Ready(Some(Ok(_)))
            ));
            assert!(stream.stall_after_offer);
        }

        #[cfg(feature = "fault-wrong-role-offer-tag")]
        #[test]
        fn wrong_role_fault_changes_only_the_encoded_offer_tag() {
            let session = [0x72; 32];
            let role = Activation128KiBDeriverB::new(session).expect("fixture role");
            let RelayStep::Send { message, .. } =
                role.handle(RelayEvent::Advance).expect("initial offer")
            else {
                panic!("B must emit the offer first");
            };
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session)
                    .expect("encoder");
            let envelope = encoder.encode(message).expect("legitimate offer envelope");
            assert_eq!(envelope[9], 1);
            let corrupted =
                inject_wrong_role_offer_tag(envelope.clone(), WireMessageKind::BaseOtOffer);
            assert_eq!(corrupted[9], 2);
            assert_eq!(&corrupted[..9], &envelope[..9]);
            assert_eq!(&corrupted[10..], &envelope[10..]);

            let mut decoder =
                EnvelopeDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("decoder");
            assert_eq!(decoder.push_once(&corrupted), Err(AdapterError::Envelope));
        }

        #[cfg(feature = "fault-session-mismatch")]
        #[test]
        fn session_mismatch_fault_preserves_a_distinct_nonzero_role_session() {
            let framing_session = [0x73; 32];
            let mapped = role_session(framing_session);
            assert_ne!(mapped, framing_session);
            assert!(mapped.iter().any(|byte| *byte != 0));

            let mut sparse_framing_session = [0_u8; 32];
            sparse_framing_session[0] = 0x80;
            let sparse_mapped = role_session(sparse_framing_session);
            assert_ne!(sparse_mapped, sparse_framing_session);
            assert!(sparse_mapped.iter().any(|byte| *byte != 0));
        }

        #[cfg(feature = "fault-short-timeout")]
        #[test]
        fn timeout_fault_uses_the_short_fixed_bound() {
            assert_eq!(CEREMONY_TIMEOUT, std::time::Duration::from_millis(250));
        }

        #[cfg(any(
            feature = "deriver-a",
            feature = "deriver-a-cross-account",
            feature = "deriver-a-same-account-websocket"
        ))]
        #[test]
        fn dropping_outbound_body_cancels_eof_without_minting_evidence() {
            let session = [0x18; 32];
            let (_sender, receiver) = mpsc::channel(0);
            let (eof_sender, mut eof_receiver) = oneshot::channel();
            let (_clock, timing) = manual_timing(0.0);
            let stream = OutboundEnvelopeStream::new(session, receiver, eof_sender, timing)
                .expect("outbound");
            drop(stream);

            let result = eof_receiver
                .try_recv()
                .expect("EOF signal channel")
                .expect("drop result");
            assert!(matches!(result, Err(AdapterError::OutboundEof)));
        }

        #[test]
        fn delayed_receiver_keeps_exactly_one_outbound_envelope_queued() {
            let (first, second) = first_a_messages([0x3d; 32]);
            let (mut sender, mut receiver) = mpsc::channel(0);
            sender
                .try_send(first)
                .expect("first envelope occupies the slot");
            let blocked = sender
                .try_send(second)
                .expect_err("second envelope must observe backpressure");
            assert!(blocked.is_full());
            let second = blocked.into_inner();
            let _first = receiver.try_recv().expect("receiver advances one envelope");
            sender
                .try_send(second)
                .expect("slot reopens only after the receiver advances");
        }

        #[test]
        fn adapter_io_metrics_count_exact_secret_ingress_and_outgoing_copies() {
            let mut metrics = AdapterIoMetrics::default();
            metrics.record_incoming_fragment(5).expect("fragment one");
            metrics.record_incoming_fragment(3).expect("fragment two");
            metrics.record_outgoing_envelope(7).expect("envelope one");
            metrics.record_outgoing_envelope(11).expect("envelope two");

            assert_eq!(metrics.total_incoming_body_bytes(), 8);
            assert_eq!(metrics.max_incoming_platform_fragment_bytes(), 5);
            assert_eq!(metrics.adapter_secret_ingress_rust_copy_bytes(), 8);
            assert_eq!(metrics.adapter_secret_ingress_js_overwrite_bytes(), 8);
            assert_eq!(metrics.total_outgoing_envelope_bytes(), 18);
            assert_eq!(metrics.peak_outgoing_envelope_bytes(), 11);
            assert_eq!(metrics.workers_rs_outgoing_stream_body_copy_bytes(), 18);
            assert_eq!(metrics.injected_outgoing_fragment_count(), 0);
            assert_eq!(metrics.max_injected_outgoing_fragment_bytes(), 0);
            assert_eq!(ADAPTER_SECRET_INGRESS_RUST_COPY_PASSES, 1);
            assert_eq!(WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES, 1);
            assert_eq!(MAX_QUEUED_OUTGOING_ENVELOPES, 1);
        }

        #[cfg(feature = "fault-fragmentation")]
        #[test]
        fn deterministic_fragmentation_preserves_bytes_and_reports_its_own_boundary() {
            let original = Bytes::from_static(&[0xa5; 16_384]);
            let mut fragments = DeterministicFragments::new(original.clone());
            let mut reconstructed = Vec::with_capacity(original.len());
            let mut metrics = AdapterIoMetrics::default();
            while let Some(fragment) = fragments.next() {
                metrics
                    .record_injected_outgoing_fragment(fragment.len())
                    .expect("fragment metric");
                reconstructed.extend_from_slice(&fragment);
            }
            assert_eq!(reconstructed, original);
            assert!(metrics.injected_outgoing_fragment_count() > 5);
            assert_eq!(metrics.max_injected_outgoing_fragment_bytes(), 4096);
        }

        #[test]
        fn adapter_errors_expose_only_stable_nonsecret_codes() {
            assert_eq!(AdapterError::Envelope.code(), "YAOS_AB_ENVELOPE");
            assert_eq!(
                AdapterError::DeploymentIdentity.code(),
                "YAOS_AB_DEPLOYMENT_IDENTITY"
            );
            assert_eq!(
                AdapterError::ProtocolState.to_string(),
                "YAOS_AB_PROTOCOL_STATE"
            );
        }
    }
}

#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket"
))]
fn json_response(
    status: http::StatusCode,
    body: String,
) -> worker::Result<http::Response<http_body_util::Full<bytes::Bytes>>> {
    Ok(http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))?)
}

#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket"
))]
fn deriver_a_report(result: &adapter::DeriverABenchmarkCompletion, elapsed_ms: f64) -> String {
    let completion = result.completion();
    let metrics = completion.stream_metrics();
    let wire = completion.wire_byte_ledger();
    let io_metrics = result.io_metrics();
    let placement = result.placement();
    let timings = result.timings();
    let client_package_bytes = completion.client_package().as_bytes().len();
    let signing_worker_package_bytes = completion.signing_worker_package().as_bytes().len();
    let mut report = serde_json::json!({
        "ok": true,
        "benchmark": "phase9b-cloudflare-activation-128kib",
        "benchmark_only": true,
        "role": "deriver-a",
        "topology": adapter::A_TOPOLOGY_LABEL,
        "family": "activation",
        "profile": "128KiB",
        "workers_rs_version": adapter::WORKERS_RS_VERSION,
        "deriver_a_colo": placement.deriver_a_colo().map(adapter::Colo::as_str),
        "deriver_b_colo": placement.deriver_b_colo().map(adapter::Colo::as_str),
        "elapsed_ms": elapsed_ms,
        "timing_semantics": "worker-date-now;deployed-advances-after-io;milestones-relative-to-deriver-a-protocol-start",
        "table_timing_boundary": adapter::TABLE_TIMING_BOUNDARY,
        "body_byte_timing_boundary": adapter::BODY_BYTE_TIMING_BOUNDARY,
        "b_response_headers_received_ms": timings.b_response_headers_received_ms(),
        "offer_received_ms": timings.offer_received_ms(),
        "extension_received_ms": timings.extension_received_ms(),
        "first_table_frame_accepted_ms": timings.first_table_frame_accepted_ms(),
        "last_table_frame_accepted_ms": timings.last_table_frame_accepted_ms(),
        "translation_accepted_ms": timings.translation_accepted_ms(),
        "request_direction_closed_ms": timings.request_direction_closed_ms(),
        "returned_received_ms": timings.returned_received_ms(),
        "response_eof_complete_ms": timings.response_eof_complete_ms(),
        "table_stream_duration_ms": timings.table_stream_duration_ms(),
        "total_protocol_duration_ms": timings.total_protocol_duration_ms(),
        "table_payload_bytes": metrics.table_payload_bytes(),
        "body_bytes": metrics.body_bytes(),
        "frame_count": metrics.frame_count(),
        "peak_table_buffer_bytes": metrics.combined_peak_table_buffer_bytes(),
        "client_package_bytes": client_package_bytes,
        "signing_worker_package_bytes": signing_worker_package_bytes,
        "total_incoming_body_bytes": io_metrics.total_incoming_body_bytes(),
        "max_incoming_platform_fragment_bytes": io_metrics.max_incoming_platform_fragment_bytes(),
        "total_outgoing_envelope_bytes": io_metrics.total_outgoing_envelope_bytes(),
        "peak_outgoing_envelope_bytes": io_metrics.peak_outgoing_envelope_bytes(),
        "workers_rs_outgoing_stream_body_copy_passes": adapter::WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES,
        "workers_rs_outgoing_stream_body_copy_bytes": io_metrics.workers_rs_outgoing_stream_body_copy_bytes(),
        "injected_outgoing_fragment_count": io_metrics.injected_outgoing_fragment_count(),
        "max_injected_outgoing_fragment_bytes": io_metrics.max_injected_outgoing_fragment_bytes(),
        "max_queued_outgoing_envelopes": adapter::MAX_QUEUED_OUTGOING_ENVELOPES,
    });
    add_body_byte_timing_fields(&mut report, timings);
    adapter::add_deployment_id_field(&mut report, result.deployment_id());
    adapter::add_secret_ingress_copy_fields(&mut report, io_metrics);
    adapter::add_wire_fields(&mut report, wire);
    adapter::add_nonpromotion_fields(&mut report);
    report.to_string()
}

#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket"
))]
fn add_body_byte_timing_fields(
    report: &mut serde_json::Value,
    timings: adapter::TransportPhaseTimings,
) {
    let object = report
        .as_object_mut()
        .expect("benchmark reports are constructed as JSON objects");
    for (field, value) in [
        (
            "b_to_a_first_body_byte_received_ms",
            timings.b_to_a_first_body_byte_received_ms(),
        ),
        (
            "a_to_b_first_body_byte_emitted_ms",
            timings.a_to_b_first_body_byte_emitted_ms(),
        ),
        (
            "a_to_b_final_body_byte_emitted_ms",
            timings.a_to_b_final_body_byte_emitted_ms(),
        ),
        (
            "b_to_a_final_body_byte_received_ms",
            timings.b_to_a_final_body_byte_received_ms(),
        ),
    ] {
        object.insert(field.to_owned(), serde_json::Value::from(value));
    }
}

#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket"
))]
fn deriver_a_error_body(error: &str) -> String {
    serde_json::json!({
        "ok": false,
        "benchmark_only": true,
        "topology": adapter::A_TOPOLOGY_LABEL,
        "error_code": error,
    })
    .to_string()
}

/// Runs Deriver A's isolated activation benchmark endpoint.
#[cfg(any(
    feature = "deriver-a",
    feature = "deriver-a-cross-account",
    feature = "deriver-a-same-account-websocket"
))]
#[worker::event(fetch)]
pub async fn main(
    mut request: worker::HttpRequest,
    env: worker::Env,
    _context: worker::Context,
) -> worker::Result<http::Response<http_body_util::Full<bytes::Bytes>>> {
    if request.method() != http::Method::POST || request.uri().path() != adapter::BENCHMARK_PATH {
        return json_response(
            http::StatusCode::NOT_FOUND,
            deriver_a_error_body("YAOS_AB_ENDPOINT_NOT_FOUND"),
        );
    }
    let deployment_id = match adapter::deployment_id(&env) {
        Ok(deployment_id) => deployment_id,
        Err(error) => {
            return json_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                deriver_a_error_body(error.code()),
            )
        }
    };
    let deriver_a_colo = match adapter::incoming_colo(&request) {
        Ok(colo) => colo,
        Err(error) => {
            return json_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                deriver_a_error_body(error.code()),
            )
        }
    };
    if let Err(error) = adapter::require_empty_public_request_body(request.body_mut()).await {
        worker::console_error!(
            "{{\"event\":\"ed25519_yao_benchmark_a_rejected\",\"benchmark_only\":true,\"role\":\"deriver-a\",\"topology\":\"{}\",\"error_code\":\"{}\"}}",
            adapter::A_TOPOLOGY_LABEL,
            error.code(),
        );
        return json_response(
            http::StatusCode::BAD_REQUEST,
            deriver_a_error_body(error.code()),
        );
    }
    let started_ms = worker::js_sys::Date::now();
    let session = match adapter::random_session() {
        Ok(session) => session,
        Err(_) => {
            return json_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                deriver_a_error_body("YAOS_AB_RANDOMNESS"),
            )
        }
    };
    match adapter::run_deriver_a_with_timeout(&env, deployment_id, session, deriver_a_colo).await {
        Ok(completion) => {
            let report = deriver_a_report(&completion, worker::js_sys::Date::now() - started_ms);
            worker::console_log!("{}", report);
            json_response(http::StatusCode::OK, report)
        }
        Err(error) => {
            worker::console_error!(
                "{{\"event\":\"ed25519_yao_benchmark_a_failed\",\"benchmark\":\"phase9b-cloudflare-activation-128kib\",\"benchmark_only\":true,\"role\":\"deriver-a\",\"topology\":\"{}\",\"family\":\"activation\",\"profile\":\"128KiB\",\"workers_rs_version\":\"{}\",\"error_code\":\"{}\"}}",
                adapter::A_TOPOLOGY_LABEL,
                adapter::WORKERS_RS_VERSION,
                error.code()
            );
            json_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                deriver_a_error_body(error.code()),
            )
        }
    }
}

#[cfg(feature = "deriver-b")]
type DeriverBBody = http_body_util::Either<
    http_body_util::StreamBody<adapter::DeriverBResponseStream>,
    http_body_util::Full<bytes::Bytes>,
>;

#[cfg(feature = "deriver-b")]
fn deriver_b_error_response(
    status: http::StatusCode,
    error_code: &'static str,
) -> worker::Result<http::Response<DeriverBBody>> {
    Ok(http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(http_body_util::Either::Right(http_body_util::Full::new(
            bytes::Bytes::from(
                serde_json::json!({
                    "ok": false,
                    "benchmark_only": true,
                    "topology": adapter::B_TOPOLOGY_LABEL,
                    "error_code": error_code,
                })
                .to_string(),
            ),
        )))?)
}

#[cfg(feature = "deriver-b")]
fn request_session(headers: &http::HeaderMap) -> Result<[u8; 32], adapter::AdapterError> {
    let encoded = headers
        .get(adapter::SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(adapter::AdapterError::Envelope)?;
    adapter::decode_session(encoded)
}

/// Serves Deriver B's isolated activation benchmark stream.
#[cfg(feature = "deriver-b")]
#[worker::event(fetch)]
pub async fn main(
    request: worker::web_sys::Request,
    env: worker::Env,
    _context: worker::Context,
) -> worker::Result<http::Response<impl http_body::Body<Data = bytes::Bytes>>> {
    let request_url = url::Url::parse(&request.url());
    if request.method() != http::Method::POST.as_str()
        || request_url.as_ref().map(url::Url::path) != Ok(adapter::BENCHMARK_PATH)
    {
        return deriver_b_error_response(http::StatusCode::NOT_FOUND, "YAOS_AB_ENDPOINT_NOT_FOUND");
    }
    let inbound = match request.body().map(adapter::SecretIncomingBody::new) {
        Some(Ok(inbound)) => inbound,
        Some(Err(error)) => {
            return deriver_b_error_response(http::StatusCode::BAD_REQUEST, error.code())
        }
        None => adapter::SecretIncomingBody::empty(),
    };
    let headers = match adapter::header_map_from_web_headers(request.headers()) {
        Ok(headers) => headers,
        Err(error) => return deriver_b_error_response(http::StatusCode::BAD_REQUEST, error.code()),
    };
    let deployment_id = match adapter::deployment_id(&env) {
        Ok(deployment_id) => deployment_id,
        Err(error) => {
            adapter::log_b_failure(error);
            return deriver_b_error_response(http::StatusCode::PRECONDITION_FAILED, error.code());
        }
    };
    if let Err(error) = adapter::require_matching_deployment_id_header(&headers, &deployment_id) {
        adapter::log_b_failure(error);
        return deriver_b_error_response(http::StatusCode::PRECONDITION_FAILED, error.code());
    }
    let session = match request_session(&headers) {
        Ok(session) => session,
        Err(error) => return deriver_b_error_response(http::StatusCode::BAD_REQUEST, error.code()),
    };
    let deriver_a_colo =
        match adapter::optional_colo_header(&headers, adapter::DERIVER_A_COLO_HEADER) {
            Ok(colo) => colo,
            Err(error) => {
                return deriver_b_error_response(http::StatusCode::BAD_REQUEST, error.code())
            }
        };
    let deriver_b_colo = match adapter::raw_incoming_colo(&request) {
        Ok(colo) => colo,
        Err(error) => {
            return deriver_b_error_response(http::StatusCode::INTERNAL_SERVER_ERROR, error.code())
        }
    };
    let deriver_b_colo_header = match deriver_b_colo
        .as_ref()
        .map(adapter::Colo::header_value)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => {
            return deriver_b_error_response(http::StatusCode::INTERNAL_SERVER_ERROR, error.code())
        }
    };
    let deployment_id_header = match deployment_id.header_value() {
        Ok(value) => value,
        Err(error) => {
            return deriver_b_error_response(http::StatusCode::INTERNAL_SERVER_ERROR, error.code())
        }
    };
    let mut response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(adapter::DEPLOYMENT_ID_HEADER, deployment_id_header);
    if let Some(colo) = deriver_b_colo_header {
        response = response.header(adapter::DERIVER_B_COLO_HEADER, colo);
    }
    let placement = adapter::PlacementEvidence::new(deriver_a_colo, deriver_b_colo);
    let stream =
        match adapter::DeriverBResponseStream::new(deployment_id, session, inbound, placement) {
            Ok(stream) => stream,
            Err(error) => {
                return deriver_b_error_response(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    error.code(),
                )
            }
        };
    Ok(response.body(http_body_util::Either::Left(
        http_body_util::StreamBody::new(stream),
    ))?)
}

#[cfg(any(
    feature = "deriver-b-cross-account",
    feature = "deriver-b-same-account-websocket"
))]
fn deriver_b_websocket_error_response(
    status: http::StatusCode,
    error: adapter::AdapterError,
) -> worker::Result<worker::Response> {
    let headers = worker::Headers::new();
    headers.set(http::header::CACHE_CONTROL.as_str(), "no-store")?;
    Ok(worker::Response::from_json(&serde_json::json!({
        "ok": false,
        "benchmark_only": true,
        "topology": adapter::B_TOPOLOGY_LABEL,
        "error_code": error.code(),
    }))?
    .with_headers(headers)
    .with_status(status.as_u16()))
}

/// Upgrades Deriver B to the fixed binary WebSocket benchmark transport.
#[cfg(any(
    feature = "deriver-b-cross-account",
    feature = "deriver-b-same-account-websocket"
))]
#[worker::event(fetch)]
pub async fn main(
    request: worker::web_sys::Request,
    env: worker::Env,
    context: worker::Context,
) -> worker::Result<worker::Response> {
    let request_url = url::Url::parse(&request.url());
    if request.method() != http::Method::GET.as_str()
        || request_url.as_ref().map(url::Url::path) != Ok(adapter::BENCHMARK_PATH)
    {
        return deriver_b_websocket_error_response(
            http::StatusCode::NOT_FOUND,
            adapter::AdapterError::WebSocket,
        );
    }
    let headers = match adapter::header_map_from_web_headers(request.headers()) {
        Ok(headers) => headers,
        Err(error) => {
            return deriver_b_websocket_error_response(http::StatusCode::BAD_REQUEST, error)
        }
    };
    if !headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    {
        return deriver_b_websocket_error_response(
            http::StatusCode::UPGRADE_REQUIRED,
            adapter::AdapterError::WebSocket,
        );
    }
    let protocol = match headers
        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
    {
        Some(protocol) => protocol.to_owned(),
        None => {
            return deriver_b_websocket_error_response(
                http::StatusCode::BAD_REQUEST,
                adapter::AdapterError::WebSocket,
            )
        }
    };
    let (protocol_deployment_id, session) = match adapter::parse_websocket_protocol(&protocol) {
        Ok(binding) => binding,
        Err(error) => {
            return deriver_b_websocket_error_response(http::StatusCode::BAD_REQUEST, error)
        }
    };
    let deployment_id = match adapter::deployment_id(&env) {
        Ok(deployment_id) => deployment_id,
        Err(error) => {
            adapter::log_b_failure(error);
            return deriver_b_websocket_error_response(
                http::StatusCode::PRECONDITION_FAILED,
                error,
            );
        }
    };
    if protocol_deployment_id != deployment_id {
        return deriver_b_websocket_error_response(
            http::StatusCode::PRECONDITION_FAILED,
            adapter::AdapterError::DeploymentIdentity,
        );
    }
    let deriver_b_colo = match adapter::raw_incoming_colo(&request) {
        Ok(colo) => colo,
        Err(error) => {
            return deriver_b_websocket_error_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                error,
            )
        }
    };
    let placement = adapter::PlacementEvidence::new(None, deriver_b_colo);
    let pair = worker::WebSocketPair::new()?;
    let server = pair.server;
    let server_for_error = server.clone();
    context.wait_until(async move {
        if let Err(error) =
            adapter::run_deriver_b_websocket(server, deployment_id, session, placement).await
        {
            adapter::log_b_failure(error);
            let _ignored = server_for_error.close(Some(1011), Some(error.code()));
        }
    });

    let response_headers = worker::Headers::new();
    response_headers.set(http::header::SEC_WEBSOCKET_PROTOCOL.as_str(), &protocol)?;
    response_headers.set(http::header::CACHE_CONTROL.as_str(), "no-store")?;
    Ok(worker::Response::from_websocket(pair.client)?.with_headers(response_headers))
}
