use std::collections::BTreeSet;

use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    canonical_lifecycle_continuity_corpus_v1, LifecycleContinuityCorpusV1,
    LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1, LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1,
    RECOVERY_ACTIVATION_CASE_ID_V1, RECOVERY_CONTINUITY_CASE_ID_V1, REFRESH_ACTIVATION_CASE_ID_V1,
    REFRESH_CONTINUITY_CASE_ID_V1, REGISTRATION_ACTIVATION_CASE_ID_V1,
    REGISTRATION_CANDIDATE_CASE_ID_V1,
};
use serde_json::{Map, Value};

const SOURCE: &str = include_str!("../src/lifecycle_fixtures.rs");
const PUBLIC_STATE_POINTERS: [&str; 11] = [
    "/cases/0/vector/pending_public",
    "/cases/1/vector/transition/pending_public",
    "/cases/1/vector/transition/activated_public",
    "/cases/2/vector/before_public",
    "/cases/2/vector/pending_public",
    "/cases/3/vector/transition/pending_public",
    "/cases/3/vector/transition/activated_public",
    "/cases/4/vector/before_public",
    "/cases/4/vector/pending_public",
    "/cases/5/vector/transition/pending_public",
    "/cases/5/vector/transition/activated_public",
];
const FORBIDDEN_PUBLIC_FIELDS: [&str; 10] = [
    "secret_root_hex",
    "secret_contribution_hex",
    "secret_delta_hex",
    "joined_seed_hex",
    "sha512_digest_hex",
    "clamped_scalar_bytes_hex",
    "signing_scalar_hex",
    "x_client_base_hex",
    "x_server_base_hex",
    "authorized_seed_hex",
];

#[test]
fn corpus_has_the_exact_six_case_sequence_and_scope() {
    let corpus = canonical_lifecycle_continuity_corpus_v1();
    assert_eq!(corpus.schema, LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1);
    assert_eq!(corpus.protocol_id, "router_ab_ed25519_yao_v1");
    assert_eq!(
        corpus.evidence_scope,
        LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1
    );

    let value = corpus_value();
    let cases = array(&value["cases"]);
    assert_eq!(cases.len(), 6);
    assert_case(cases, 0, "registration", REGISTRATION_CANDIDATE_CASE_ID_V1);
    assert_case(cases, 1, "activation", REGISTRATION_ACTIVATION_CASE_ID_V1);
    assert_case(cases, 2, "recovery", RECOVERY_CONTINUITY_CASE_ID_V1);
    assert_case(cases, 3, "activation", RECOVERY_ACTIVATION_CASE_ID_V1);
    assert_case(cases, 4, "refresh", REFRESH_CONTINUITY_CASE_ID_V1);
    assert_case(cases, 5, "activation", REFRESH_ACTIVATION_CASE_ID_V1);
    assert_eq!(cases[1]["vector"]["origin_kind"], "registration");
    assert_eq!(cases[3]["vector"]["origin_kind"], "recovery");
    assert_eq!(cases[5]["vector"]["origin_kind"], "refresh");

    let case_ids: BTreeSet<_> = cases.iter().map(case_id).collect();
    assert_eq!(case_ids.len(), cases.len());
}

#[test]
fn registration_candidate_is_public_metadata_with_zero_represented_work() {
    let value = corpus_value();
    let registration = &array(&value["cases"])[0]["vector"];
    let pending = &registration["pending_public"];
    assert_eq!(
        pending["candidate_role_epochs"]["deriver_a"]["role_root_epoch"],
        3
    );
    assert_eq!(
        pending["candidate_role_epochs"]["deriver_a"]["role_input_state_epoch"],
        11
    );
    assert_eq!(
        pending["candidate_role_epochs"]["deriver_b"]["role_root_epoch"],
        9
    );
    assert_eq!(
        pending["candidate_role_epochs"]["deriver_b"]["role_input_state_epoch"],
        41
    );
    assert_eq!(pending["pending_activation_epoch"], 7);
    for count in object(&registration["reference_operation_counts"]).values() {
        assert_eq!(unsigned(count), 0);
    }
    assert_no_forbidden_public_keys(registration);
}

#[test]
fn same_root_recovery_preserves_every_contribution_trace_and_public_identity() {
    let value = corpus_value();
    let recovery = &array(&value["cases"])[2]["vector"];
    let host = &recovery["host_only_reference"];
    assert_eq!(
        host["recovered_client_root_hex"],
        host["synthetic_roots"]["client_root_hex"]
    );
    assert_eq!(host["current_contributions"], host["after_contributions"]);
    assert_eq!(
        host["before_clear_reference_trace"],
        host["after_clear_reference_trace"]
    );
    assert_eq!(
        recovery["before_public"]["identity"],
        recovery["pending_public"]["identity"]
    );
    assert_eq!(
        recovery["before_public"]["active_role_epochs"],
        recovery["pending_public"]["current_role_epochs"]
    );
    assert!(
        unsigned(&recovery["pending_public"]["pending_activation_epoch"])
            > unsigned(&recovery["before_public"]["active_activation_epoch"])
    );

    let current = object(&host["current_contributions"]);
    let rederived = object(&host["rederived_client_contributions"]);
    for field in [
        "y_client_a_hex",
        "tau_client_a_hex",
        "y_client_b_hex",
        "tau_client_b_hex",
    ] {
        assert_eq!(current[field], rederived[field], "changed {field}");
    }

    let counts = object(&recovery["reference_operation_counts"]);
    assert_eq!(unsigned(&counts["deriver_a_invocations"]), 1);
    assert_eq!(unsigned(&counts["deriver_b_invocations"]), 1);
    assert_eq!(unsigned(&counts["client_kdf_derivations_a"]), 1);
    assert_eq!(unsigned(&counts["client_kdf_derivations_b"]), 1);
    assert_eq!(unsigned(&counts["server_kdf_derivations_a"]), 0);
    assert_eq!(unsigned(&counts["server_kdf_derivations_b"]), 0);
    assert_eq!(unsigned(&counts["activation_family_evaluations"]), 1);
    assert_eq!(unsigned(&counts["export_family_evaluations"]), 0);
    assert_eq!(unsigned(&counts["pending_activation_consumptions"]), 0);
}

#[test]
fn refresh_applies_opposite_nonzero_deltas_and_preserves_the_joined_trace() {
    let value = corpus_value();
    let refresh = &array(&value["cases"])[4]["vector"];
    let host = &refresh["host_only_reference"];
    let before = object(&host["before_contributions"]);
    let after = object(&host["after_contributions"]);
    let delta = &host["delta"];
    let deriver_a_delta_y = hex_32(string(&delta["deriver_a"]["delta_y_hex"]));
    let deriver_b_delta_y = hex_32(string(&delta["deriver_b"]["delta_y_hex"]));
    let deriver_a_delta_tau = scalar(string(&delta["deriver_a"]["delta_tau_hex"]));
    let deriver_b_delta_tau = scalar(string(&delta["deriver_b"]["delta_tau_hex"]));
    let delta_y = hex_32(string(&delta["combined_delta_y_hex"]));
    let delta_tau = scalar(string(&delta["combined_delta_tau_hex"]));
    assert_eq!(
        wrapping_add_256(deriver_a_delta_y, deriver_b_delta_y),
        delta_y
    );
    assert_eq!(deriver_a_delta_tau + deriver_b_delta_tau, delta_tau);
    assert_ne!(delta_y, [0u8; 32]);
    assert_ne!(delta_tau, Scalar::ZERO);

    assert_eq!(
        hex_32(string(&after["y_server_a_hex"])),
        wrapping_add_256(hex_32(string(&before["y_server_a_hex"])), delta_y)
    );
    assert_eq!(
        hex_32(string(&after["y_server_b_hex"])),
        wrapping_sub_256(hex_32(string(&before["y_server_b_hex"])), delta_y)
    );
    assert_eq!(
        scalar(string(&after["tau_server_a_hex"])),
        scalar(string(&before["tau_server_a_hex"])) + delta_tau
    );
    assert_eq!(
        scalar(string(&after["tau_server_b_hex"])),
        scalar(string(&before["tau_server_b_hex"])) - delta_tau
    );
    for field in [
        "y_client_a_hex",
        "tau_client_a_hex",
        "y_client_b_hex",
        "tau_client_b_hex",
    ] {
        assert_eq!(before[field], after[field], "changed {field}");
    }
    let before_trace = object(&host["before_clear_reference_trace"]);
    let after_trace = object(&host["after_clear_reference_trace"]);
    assert_eq!(
        hex_32(string(&after_trace["y_a_hex"])),
        wrapping_add_256(hex_32(string(&before_trace["y_a_hex"])), delta_y)
    );
    assert_eq!(
        hex_32(string(&after_trace["y_b_hex"])),
        wrapping_sub_256(hex_32(string(&before_trace["y_b_hex"])), delta_y)
    );
    assert_eq!(
        scalar(string(&after_trace["tau_a_hex"])),
        scalar(string(&before_trace["tau_a_hex"])) + delta_tau
    );
    assert_eq!(
        scalar(string(&after_trace["tau_b_hex"])),
        scalar(string(&before_trace["tau_b_hex"])) - delta_tau
    );
    assert_refresh_identity_trace_equal(before_trace, after_trace);
    assert_eq!(
        refresh["before_public"]["identity"],
        refresh["pending_public"]["identity"]
    );

    let current_epochs = &refresh["pending_public"]["current_role_epochs"];
    let next_epochs = &refresh["pending_public"]["next_role_epochs"];
    for role in ["deriver_a", "deriver_b"] {
        assert_eq!(
            current_epochs[role]["role_root_epoch"],
            next_epochs[role]["role_root_epoch"]
        );
        assert!(
            unsigned(&next_epochs[role]["role_input_state_epoch"])
                > unsigned(&current_epochs[role]["role_input_state_epoch"])
        );
    }
    assert_eq!(refresh["pending_public"]["derivation_admission"], "frozen");
    assert!(
        unsigned(&refresh["pending_public"]["pending_activation_epoch"])
            > unsigned(&refresh["before_public"]["active_activation_epoch"])
    );

    let counts = object(&refresh["reference_operation_counts"]);
    assert_eq!(unsigned(&counts["deriver_a_invocations"]), 1);
    assert_eq!(unsigned(&counts["deriver_b_invocations"]), 1);
    assert_eq!(unsigned(&counts["activation_family_evaluations"]), 1);
    for field in [
        "client_kdf_derivations_a",
        "client_kdf_derivations_b",
        "server_kdf_derivations_a",
        "server_kdf_derivations_b",
        "export_family_evaluations",
        "pending_activation_consumptions",
    ] {
        assert_eq!(unsigned(&counts[field]), 0, "nonzero {field}");
    }
}

#[test]
fn activation_cases_copy_origin_state_promote_once_and_evaluate_nothing() {
    let value = corpus_value();
    let cases = array(&value["cases"]);
    let registration_pending = &cases[0]["vector"]["pending_public"];
    let registration_activation = &cases[1]["vector"]["transition"];
    assert_eq!(
        registration_activation["origin_case_id"],
        REGISTRATION_CANDIDATE_CASE_ID_V1
    );
    assert_eq!(
        &registration_activation["pending_public"],
        registration_pending
    );
    assert_eq!(
        registration_activation["activated_public"]["identity"],
        registration_pending["identity"]
    );
    assert_eq!(
        registration_activation["activated_public"]["active_role_epochs"],
        registration_pending["candidate_role_epochs"]
    );
    assert_eq!(
        registration_activation["activated_public"]["active_activation_epoch"],
        registration_pending["pending_activation_epoch"]
    );

    let recovery_pending = &cases[2]["vector"]["pending_public"];
    let recovery_activation = &cases[3]["vector"]["transition"];
    assert_eq!(
        recovery_activation["origin_case_id"],
        RECOVERY_CONTINUITY_CASE_ID_V1
    );
    assert_eq!(&recovery_activation["pending_public"], recovery_pending);
    assert_eq!(
        recovery_activation["activated_public"]["identity"],
        recovery_pending["identity"]
    );
    assert_eq!(
        recovery_activation["activated_public"]["active_role_epochs"],
        recovery_pending["current_role_epochs"]
    );
    assert_eq!(
        recovery_activation["activated_public"]["active_activation_epoch"],
        recovery_pending["pending_activation_epoch"]
    );

    let refresh_pending = &cases[4]["vector"]["pending_public"];
    let refresh_activation = &cases[5]["vector"]["transition"];
    assert_eq!(
        refresh_activation["origin_case_id"],
        REFRESH_CONTINUITY_CASE_ID_V1
    );
    assert_eq!(&refresh_activation["pending_public"], refresh_pending);
    assert_eq!(
        refresh_activation["activated_public"]["identity"],
        refresh_pending["identity"]
    );
    assert_eq!(
        refresh_activation["activated_public"]["active_role_epochs"],
        refresh_pending["next_role_epochs"]
    );
    assert_eq!(
        refresh_activation["activated_public"]["active_activation_epoch"],
        refresh_pending["pending_activation_epoch"]
    );
    assert_eq!(
        refresh_activation["activated_public"]["derivation_admission"],
        "open"
    );
    assert_eq!(
        refresh_activation["activated_public"]["retired_role_input_state_epochs"]["deriver_a"],
        refresh_pending["current_role_epochs"]["deriver_a"]["role_input_state_epoch"]
    );
    assert_eq!(
        refresh_activation["activated_public"]["retired_role_input_state_epochs"]["deriver_b"],
        refresh_pending["current_role_epochs"]["deriver_b"]["role_input_state_epoch"]
    );

    for activation in [
        registration_activation,
        recovery_activation,
        refresh_activation,
    ] {
        let counts = object(&activation["reference_operation_counts"]);
        for field in [
            "deriver_a_invocations",
            "deriver_b_invocations",
            "client_kdf_derivations_a",
            "client_kdf_derivations_b",
            "server_kdf_derivations_a",
            "server_kdf_derivations_b",
            "activation_family_evaluations",
            "export_family_evaluations",
        ] {
            assert_eq!(unsigned(&counts[field]), 0, "nonzero {field}");
        }
        assert_eq!(unsigned(&counts["pending_activation_consumptions"]), 1);
    }
}

#[test]
fn activation_shapes_are_structurally_incapable_of_carrying_secret_inputs() {
    let value = corpus_value();
    let cases = array(&value["cases"]);
    for case_index in [1usize, 3usize, 5usize] {
        let activation = object(&cases[case_index]["vector"]["transition"]);
        let actual_keys: BTreeSet<&str> = activation.keys().map(String::as_str).collect();
        assert_eq!(
            actual_keys,
            BTreeSet::from([
                "activated_public",
                "case_id",
                "origin_case_id",
                "pending_public",
                "reference_operation_counts",
            ])
        );
        assert_no_forbidden_public_keys(&cases[case_index]["vector"]);
    }
    assert_no_forbidden_public_keys(&cases[0]["vector"]["pending_public"]);
    for case_index in [2usize, 4usize] {
        assert_no_forbidden_public_keys(&cases[case_index]["vector"]["before_public"]);
        assert_no_forbidden_public_keys(&cases[case_index]["vector"]["pending_public"]);
    }

    for pointer in PUBLIC_STATE_POINTERS {
        for field in FORBIDDEN_PUBLIC_FIELDS {
            let mut mutated = value.clone();
            object_mut(
                mutated
                    .pointer_mut(pointer)
                    .expect("public-state JSON pointer exists"),
            )
            .insert(field.to_owned(), Value::String("00".to_owned()));
            assert_decode_rejected(mutated);
        }
    }

    for case_index in [1usize, 3usize, 5usize] {
        for field in [
            "host_only_reference",
            "packages",
            "proof",
            "ciphertext",
            "receipt",
            "output_share_hex",
        ] {
            let mut mutated = value.clone();
            object_mut(&mut mutated["cases"][case_index]["vector"]["transition"])
                .insert(field.to_owned(), Value::Object(Map::new()));
            assert_decode_rejected(mutated);
        }
    }
}

#[test]
fn serde_rejects_unknown_missing_and_cross_branch_fields() {
    let canonical = corpus_value();

    let mut top_unknown = canonical.clone();
    object_mut(&mut top_unknown).insert("unknown".to_owned(), Value::Bool(true));
    assert_decode_rejected(top_unknown);

    let mut nested_unknown = canonical.clone();
    object_mut(&mut nested_unknown["cases"][0]["vector"])
        .insert("unknown".to_owned(), Value::Bool(true));
    assert_decode_rejected(nested_unknown);

    let mut missing = canonical.clone();
    object_mut(&mut missing["cases"][2]["vector"]).remove("before_public");
    assert_decode_rejected(missing);

    let mut activation_with_host_inputs = canonical.clone();
    object_mut(&mut activation_with_host_inputs["cases"][1]["vector"]["transition"]).insert(
        "host_only_reference".to_owned(),
        canonical["cases"][2]["vector"]["host_only_reference"].clone(),
    );
    assert_decode_rejected(activation_with_host_inputs);

    let mut recovery_with_seed = canonical.clone();
    object_mut(&mut recovery_with_seed["cases"][2]["vector"]).insert(
        "authorized_seed_hex".to_owned(),
        Value::String("00".repeat(32)),
    );
    assert_decode_rejected(recovery_with_seed);

    let mut unsupported_request = canonical.clone();
    unsupported_request["cases"][0]["request_kind"] = Value::String("export".to_owned());
    assert_decode_rejected(unsupported_request);

    let mut unsupported_origin = canonical;
    unsupported_origin["cases"][1]["vector"]["origin_kind"] =
        Value::String("activation".to_owned());
    assert_decode_rejected(unsupported_origin);
}

#[test]
fn parsed_corpus_rejects_zero_repeated_and_regressing_epochs() {
    let canonical = corpus_value();

    let mut zero = canonical.clone();
    zero["cases"][2]["vector"]["before_public"]["active_role_epochs"]["deriver_a"]
        ["role_root_epoch"] = Value::from(0);
    assert_decode_rejected(zero);

    let mut repeated = canonical.clone();
    let current = repeated["cases"][4]["vector"]["pending_public"]["current_role_epochs"]
        ["deriver_a"]["role_input_state_epoch"]
        .clone();
    repeated["cases"][4]["vector"]["pending_public"]["next_role_epochs"]["deriver_a"]
        ["role_input_state_epoch"] = current;
    assert_decode_rejected(repeated);

    let mut regressing = canonical.clone();
    regressing["cases"][4]["vector"]["pending_public"]["next_role_epochs"]["deriver_b"]
        ["role_input_state_epoch"] = Value::from(1);
    assert_decode_rejected(regressing);

    let mut changed_recovery_root = canonical;
    changed_recovery_root["cases"][2]["vector"]["host_only_reference"]
        ["recovered_client_root_hex"] = Value::String("12".repeat(32));
    assert_decode_rejected(changed_recovery_root);
}

#[test]
fn serialization_round_trip_is_deterministic() {
    let first = serde_json::to_string_pretty(&canonical_lifecycle_continuity_corpus_v1())
        .expect("canonical corpus serializes");
    let parsed: LifecycleContinuityCorpusV1 =
        serde_json::from_str(&first).expect("canonical corpus parses");
    let second = serde_json::to_string_pretty(&parsed).expect("parsed corpus serializes");
    assert_eq!(first, second);
}

#[test]
fn activation_builder_sources_have_no_oracle_kdf_or_deriver_access() {
    for function in [
        "build_registration_activation_continuation_v1",
        "build_recovery_activation_continuation_v1",
        "build_refresh_activation_continuation_v1",
    ] {
        let body = function_source(SOURCE, function);
        for forbidden in [
            "evaluate_",
            "derive_",
            "Deriver",
            "Contribution",
            "Synthetic",
            "Kdf",
            "material",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function} contains forbidden source token {forbidden}"
            );
        }
    }
}

#[test]
fn fixture_module_has_no_product_or_legacy_dependency() {
    for forbidden in [
        "router_ab_core",
        "sdk_web",
        "cloudflare",
        "ed25519_hss",
        "wasm/",
        "apps/",
        "packages/",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "lifecycle fixture source contains forbidden dependency {forbidden}"
        );
    }
}

fn corpus_value() -> Value {
    serde_json::to_value(canonical_lifecycle_continuity_corpus_v1())
        .expect("canonical corpus serializes")
}

fn assert_case(cases: &[Value], index: usize, request_kind: &str, expected_case_id: &str) {
    assert_eq!(cases[index]["request_kind"], request_kind);
    assert_eq!(case_id(&cases[index]), expected_case_id);
}

fn case_id(case: &Value) -> &str {
    let vector = &case["vector"];
    match string(&case["request_kind"]) {
        "activation" => string(&vector["transition"]["case_id"]),
        "registration" | "recovery" | "refresh" => string(&vector["case_id"]),
        request_kind => panic!("unexpected request kind {request_kind}"),
    }
}

fn assert_no_forbidden_public_keys(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (field, nested) in fields {
                assert!(
                    !is_forbidden_public_key(field),
                    "public object contains forbidden field {field}"
                );
                assert_no_forbidden_public_keys(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_no_forbidden_public_keys(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn is_forbidden_public_key(field: &str) -> bool {
    field.ends_with("_root_hex")
        || field.ends_with("_contribution_hex")
        || field.ends_with("_delta_hex")
        || matches!(
            field,
            "joined_seed_hex"
                | "sha512_digest_hex"
                | "clamped_scalar_bytes_hex"
                | "signing_scalar_hex"
                | "x_client_base_hex"
                | "x_server_base_hex"
                | "authorized_seed_hex"
        )
}

fn assert_decode_rejected(value: Value) {
    assert!(serde_json::from_value::<LifecycleContinuityCorpusV1>(value).is_err());
}

fn assert_refresh_identity_trace_equal(before: &Map<String, Value>, after: &Map<String, Value>) {
    for field in [
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "x_client_point_hex",
        "x_server_point_hex",
        "public_key_hex",
    ] {
        assert_eq!(before[field], after[field], "changed {field}");
    }
}

fn function_source<'a>(source: &'a str, function: &str) -> &'a str {
    let marker = format!("fn {function}(");
    let start = source.find(&marker).expect("guarded function exists");
    let open_offset = source[start..]
        .find('{')
        .expect("guarded function has a body");
    let open = start + open_offset;
    let mut depth = 0usize;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("guarded function body is unterminated")
}

fn array(value: &Value) -> &[Value] {
    value.as_array().expect("fixture field is an array")
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("fixture field is an object")
}

fn object_mut(value: &mut Value) -> &mut Map<String, Value> {
    value.as_object_mut().expect("fixture field is an object")
}

fn string(value: &Value) -> &str {
    value.as_str().expect("fixture field is a string")
}

fn unsigned(value: &Value) -> u64 {
    value
        .as_u64()
        .expect("fixture field is an unsigned integer")
}

fn scalar(value: &str) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(hex_32(value)))
        .expect("fixture scalar is canonical")
}

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .expect("fixture contains lowercase hex");
    }
    output
}

fn wrapping_add_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = false;
    for index in 0..32 {
        let (without_carry, first_carry) = left[index].overflowing_add(right[index]);
        let (sum, second_carry) = without_carry.overflowing_add(u8::from(carry));
        output[index] = sum;
        carry = first_carry || second_carry;
    }
    output
}

fn wrapping_sub_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = false;
    for index in 0..32 {
        let (without_borrow, first_borrow) = left[index].overflowing_sub(right[index]);
        let (difference, second_borrow) = without_borrow.overflowing_sub(u8::from(borrow));
        output[index] = difference;
        borrow = first_borrow || second_borrow;
    }
    output
}
