use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const GUARDED_HELPERS: &[&str] = &[
    "add_two_local_bit_words_right_transport_bundles",
    "add_transport_bundle",
    "add_words_bits_mod_l_canonical_inputs_right_transport_bundles_local",
    "build_hidden_bit_output_bundle",
    "build_hidden_bit_output_transport_bundle_from_canonical",
    "build_hidden_bit_output_transport_bundle_pair",
    "canonicalize_hidden_bit_output_words",
    "materialize_core_bit_pair_to_arithmetic_word_pair_naive",
    "materialize_into",
    "materialize_round_sigma_into",
    "materialize_message_schedule_continuation_with_split_server_inputs_with_pool",
    "materialize_output_bundles_from_continuations_with_pool",
    "materialize_output_bundles_from_projector_inputs_with_pool",
    "materialize_projector_inputs_from_add_stage_inputs",
    "materialize_server_output_bundles_from_continuations_with_pool",
    "materialize_staged_server_execution_with_split_server_inputs_with_pool",
];

#[test]
fn hidden_eval_materialization_helpers_are_documented() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(manifest_dir.join("src/ddh/hidden_eval_executor.rs"))
        .expect("read hidden_eval_executor.rs");
    let plan = fs::read_to_string(manifest_dir.join("docs/optimization-5.md")).expect("read plan");

    let documented: BTreeSet<&str> = GUARDED_HELPERS.iter().copied().collect();
    let discovered = discover_guarded_helper_names(&source);

    let undocumented: Vec<_> = discovered.difference(&documented).copied().collect();
    assert!(
        undocumented.is_empty(),
        "new hidden-eval materialization helpers must be added to optimization-5.md: {undocumented:?}"
    );

    let missing_from_source: Vec<_> = documented.difference(&discovered).copied().collect();
    assert!(
        missing_from_source.is_empty(),
        "materialization graph guard references helpers missing from source: {missing_from_source:?}"
    );

    for helper in GUARDED_HELPERS {
        assert!(
            plan.contains(helper),
            "optimization-5.md must mention guarded helper `{helper}`"
        );
    }
}

#[test]
fn core_bit_word_pair_boundary_is_documented() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(manifest_dir.join("src/ddh/hidden_eval_executor.rs"))
        .expect("read hidden_eval_executor.rs");
    let plan = fs::read_to_string(manifest_dir.join("docs/optimization-5.md")).expect("read plan");

    assert!(
        source.contains("struct CoreBitWordPair"),
        "round-core sigma storage should use CoreBitWordPair"
    );
    let core_side_body =
        struct_body(&source, "CoreBitWordSide").expect("CoreBitWordSide body should exist");
    assert!(
        core_side_body.contains("stage: CoreBitWordStage"),
        "CoreBitWordSide should carry a required circuit stage"
    );
    assert!(
        core_side_body.contains("share_side: DdhHssShareSide"),
        "CoreBitWordSide should carry the required share side"
    );
    assert!(
        core_side_body.contains("share_blocks: Vec<u64>"),
        "CoreBitWordSide should carry packed share bits"
    );
    assert!(
        core_side_body.contains("bit_len: usize"),
        "CoreBitWordSide should carry an explicit public bit width"
    );
    assert!(
        core_side_body.contains("provenance_digests: Vec<[u8; 32]>"),
        "CoreBitWordSide should carry provenance for every bit"
    );
    assert!(
        !core_side_body.contains("commitments:"),
        "CoreBitWordSide should stay commitment-free"
    );
    let core_pair_body =
        struct_body(&source, "CoreBitWordPair").expect("CoreBitWordPair body should exist");
    assert!(
        core_pair_body.contains("stage: CoreBitWordStage"),
        "CoreBitWordPair should carry a required circuit stage"
    );
    assert!(
        core_pair_body.contains("left: CoreBitWordSide")
            && core_pair_body.contains("right: CoreBitWordSide"),
        "CoreBitWordPair should require left and right core sides"
    );
    assert!(
        source.contains("enum CoreBitWordStage"),
        "CoreBitWordStage should define explicit executor-local stages"
    );
    for stage in [
        "MessageScheduleSigma0",
        "MessageScheduleSigma1",
        "RoundCoreSigma0",
        "RoundCoreSigma1",
    ] {
        assert!(
            source.contains(stage),
            "CoreBitWordStage should include `{stage}`"
        );
    }
    assert!(
        !source.contains("RoundKernelCoreBooleanWord"),
        "obsolete round-core wrapper should stay removed"
    );
    assert!(
        source.contains("fn materialize_round_sigma_into"),
        "round sigma should materialize through an explicit boundary"
    );
    assert!(
        plan.contains("CoreBitWordPair") && plan.contains("materialize_round_sigma_into"),
        "optimization-5.md must document the core-pair boundary"
    );
}

fn discover_guarded_helper_names(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .filter_map(function_name)
        .filter(|name| {
            name.contains("materialize")
                || name.contains("canonicalize")
                || name.contains("transport_bundle")
                || name.starts_with("build_hidden_bit_output")
        })
        .collect()
}

fn function_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("fn ")
        .or_else(|| trimmed.strip_prefix("pub fn "))?;
    let end = rest.find(['(', '<'])?;
    Some(&rest[..end])
}

fn struct_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let start = source.find(&format!("struct {name} {{"))?;
    let body_start = source[start..].find('{')? + start + 1;
    let body_end = source[body_start..].find("\n}")? + body_start;
    Some(&source[body_start..body_end])
}
