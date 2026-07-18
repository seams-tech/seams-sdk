use std::fs;
use std::path::{Path, PathBuf};

struct Evidence<'a> {
    relative_path: &'a str,
    test_names: &'a [&'a str],
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("oracle crate is nested under workspace/crates")
        .to_path_buf()
}

#[test]
fn abort_corpus_references_live_executable_evidence() {
    let root = workspace_root();
    let corpus_path = root.join("crates/router-ab-ecdsa-presign/specs/abort-corpus-v1.md");
    let corpus = fs::read_to_string(corpus_path).expect("read abort corpus");
    assert!(!corpus.contains("TBD"));
    assert!(!corpus.contains("TODO"));

    let evidence = [
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/codec.rs",
            test_names: &[
                "every_fixed_round_round_trips_and_drives_new_new",
                "header_rejects_role_round_flags_length_and_trailing_bytes",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/lib.rs",
            test_names: &[
                "wrong_pair_context_aborts_before_peer_scalar_use",
                "noncanonical_peer_e_share_aborts_at_the_boundary",
                "tampered_peer_e_share_aborts_on_commitment_check",
                "tampered_alpha_aborts_on_commitment_check",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/proofs.rs",
            test_names: &[
                "client_dlog_eq_proof_verifies_and_rejects_a_tampered_response",
                "dlog_proof_role_reflection_fails",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/triples.rs",
            test_names: &[
                "altered_randomizer_aborts",
                "altered_private_share_aborts",
                "client_opening_cannot_be_reflected_as_worker_opening",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/triples/base_rot.rs",
            test_names: &[
                "degenerate_choice_point_aborts",
                "reflected_sender_role_cannot_produce_correlated_keys",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/triples/base_rot/extension.rs",
            test_names: &[
                "tampered_consistency_proof_aborts_before_sender_output",
                "tampered_acceptance_keeps_receiver_output_sealed",
                "keyed_expansion_changes_for_every_changed_base_key",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/triples/base_rot/extension/mta.rs",
            test_names: &[
                "noncanonical_ciphertext_is_rejected_at_the_boundary",
                "two_triple_bundle_requires_zero_then_one",
                "altered_ciphertext_breaks_the_terminal_product_equation",
            ],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-presign/src/triples/finalize.rs",
            test_names: &["corrupted_mta_output_fails_the_terminal_product_equation"],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-online/src/lib.rs",
            test_names: &["generated_presign_fixture_matches_oracle_finalization"],
        },
        Evidence {
            relative_path: "crates/router-ab-ecdsa-pool/src/lib.rs",
            test_names: &[
                "stale_compare_and_swap_cannot_reserve_twice",
                "late_or_substituted_commit_burns_the_original_attempt",
                "crash_and_ambiguous_recovery_are_terminal",
            ],
        },
    ];

    for owner in evidence {
        let source = fs::read_to_string(root.join(owner.relative_path))
            .unwrap_or_else(|error| panic!("read {}: {error}", owner.relative_path));
        for test_name in owner.test_names {
            assert!(
                source.contains(&format!("fn {test_name}(")),
                "missing executable evidence {test_name} in {}",
                owner.relative_path
            );
            assert!(
                corpus.contains(test_name),
                "abort corpus omitted executable evidence {test_name}"
            );
        }
    }
}
