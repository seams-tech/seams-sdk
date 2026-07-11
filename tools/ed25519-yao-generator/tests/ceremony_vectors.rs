use ed25519_yao_generator::{
    canonical_ceremony_context_vector_corpus_v1, CeremonyContextVectorCorpusV1,
    CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1, CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1,
};

#[test]
fn ceremony_corpus_is_strict_canonical_json() {
    let corpus = canonical_ceremony_context_vector_corpus_v1();
    let encoded = format!(
        "{}\n",
        serde_json::to_string_pretty(&corpus).expect("serialize")
    );
    let parsed: CeremonyContextVectorCorpusV1 =
        serde_json::from_str(&encoded).expect("strict corpus parses");
    assert_eq!(parsed, corpus);
    assert_eq!(parsed.schema, CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(
        parsed.evidence_scope,
        CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.cases.len(), 5);
}

#[test]
fn ceremony_corpus_rejects_unknown_fields() {
    let corpus = canonical_ceremony_context_vector_corpus_v1();
    let mut value = serde_json::to_value(corpus).expect("serialize corpus");
    value
        .as_object_mut()
        .expect("corpus object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<CeremonyContextVectorCorpusV1>(value).is_err());
}
