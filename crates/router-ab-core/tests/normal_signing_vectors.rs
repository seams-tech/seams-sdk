use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use router_ab_core::{
    generated_normal_signing_vector_fixture_json_v2, parse_normal_signing_vector_fixture_v2,
    validate_normal_signing_vector_fixture_v2,
};

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("normal-signing")
        .join("normal-signing-vectors-v2.json")
}

#[test]
fn committed_normal_signing_vectors_match_generator() {
    let path = fixture_path();
    if std::env::var_os("UPDATE_ROUTER_AB_NORMAL_SIGNING_VECTORS").is_some() {
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture dir");
        fs::write(
            &path,
            format!("{}\n", generated_normal_signing_vector_fixture_json_v2()),
        )
        .expect("write normal-signing fixture");
    }
    let committed = fs::read_to_string(path).expect("committed normal-signing fixture");
    let generated = format!("{}\n", generated_normal_signing_vector_fixture_json_v2());

    assert_eq!(committed, generated);
}

#[test]
fn committed_normal_signing_vectors_validate() {
    let committed = fs::read_to_string(fixture_path()).expect("committed normal-signing fixture");
    let fixture = parse_normal_signing_vector_fixture_v2(&committed).expect("parse fixture");

    validate_normal_signing_vector_fixture_v2(&fixture).expect("validate fixture");
}

#[test]
fn normal_signing_vectors_cover_all_prepare_branches() {
    let committed = fs::read_to_string(fixture_path()).expect("committed normal-signing fixture");
    let fixture = parse_normal_signing_vector_fixture_v2(&committed).expect("parse fixture");
    let branches = fixture
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let expected = [
        "near_delegate_action_v1",
        "near_transaction_v1",
        "nep413_v1",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(branches, expected);
}
