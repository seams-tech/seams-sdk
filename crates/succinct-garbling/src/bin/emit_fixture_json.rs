use succinct_garbling::fixtures::serialized_fixture_corpus_json;

fn main() {
    println!(
        "{}",
        serialized_fixture_corpus_json().expect("fixture corpus should serialize")
    );
}
