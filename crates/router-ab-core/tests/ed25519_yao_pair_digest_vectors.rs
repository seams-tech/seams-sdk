use std::fs;
use std::path::{Path, PathBuf};

use router_ab_core::{
    generated_ed25519_yao_pair_digest_vector_fixture_json_v1,
    parse_ed25519_yao_pair_digest_vector_fixture_v1,
    validate_ed25519_yao_pair_digest_vector_fixture_v1,
};

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("ed25519-yao")
        .join("pair-digest-vectors-v1.json")
}

#[test]
fn committed_pair_digest_vectors_match_generator() {
    let path = fixture_path();
    if std::env::var_os("UPDATE_ROUTER_AB_ED25519_YAO_PAIR_DIGEST_VECTORS").is_some() {
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture dir");
        fs::write(
            &path,
            format!(
                "{}\n",
                generated_ed25519_yao_pair_digest_vector_fixture_json_v1()
            ),
        )
        .expect("write pair-digest fixture");
    }

    let committed = fs::read_to_string(path).expect("committed pair-digest fixture");
    let generated = format!(
        "{}\n",
        generated_ed25519_yao_pair_digest_vector_fixture_json_v1()
    );
    assert_eq!(committed, generated);
}

#[test]
fn committed_pair_digest_vectors_validate() {
    let committed = fs::read_to_string(fixture_path()).expect("committed pair-digest fixture");
    let fixture = parse_ed25519_yao_pair_digest_vector_fixture_v1(&committed)
        .expect("parse pair-digest fixture");
    validate_ed25519_yao_pair_digest_vector_fixture_v1(&fixture)
        .expect("validate pair-digest fixture");
}
