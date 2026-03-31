use ed25519_hss::fixtures::serialized_fixture_corpus;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
            .expect("fixture corpus should serialize")
    );
}
