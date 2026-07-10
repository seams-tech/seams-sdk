use ed25519_yao_generator::{
    differential_vector_corpus_v1, DifferentialVectorError, LifecycleRequestKindV1, VectorCaseV1,
    MAX_DIFFERENTIAL_VECTOR_CASES_V1,
};

const PUBLIC_TEST_SEED: [u8; 32] = [0x5a; 32];

#[test]
fn deterministic_corpus_is_reproducible_and_cycles_request_kinds() {
    let first = differential_vector_corpus_v1(PUBLIC_TEST_SEED, 12).expect("valid corpus");
    let second = differential_vector_corpus_v1(PUBLIC_TEST_SEED, 12).expect("valid corpus");
    assert_eq!(first, second);

    let request_kinds: Vec<_> = first.cases.iter().map(VectorCaseV1::request_kind).collect();
    assert_eq!(
        request_kinds,
        [
            LifecycleRequestKindV1::Registration,
            LifecycleRequestKindV1::Activation,
            LifecycleRequestKindV1::Recovery,
            LifecycleRequestKindV1::Refresh,
            LifecycleRequestKindV1::Export,
            LifecycleRequestKindV1::Registration,
            LifecycleRequestKindV1::Activation,
            LifecycleRequestKindV1::Recovery,
            LifecycleRequestKindV1::Refresh,
            LifecycleRequestKindV1::Export,
            LifecycleRequestKindV1::Registration,
            LifecycleRequestKindV1::Activation,
        ]
    );

    let export_count = first
        .cases
        .iter()
        .filter(|case| matches!(case, VectorCaseV1::Export(_)))
        .count();
    assert_eq!(export_count, 2);
}

#[test]
fn public_test_seed_and_case_index_change_derived_inputs_and_context() {
    let baseline = differential_vector_corpus_v1(PUBLIC_TEST_SEED, 2).expect("valid corpus");
    let changed_seed = differential_vector_corpus_v1([0xa5; 32], 2).expect("valid corpus");

    let baseline_zero = reference_case(&baseline.cases[0]);
    let baseline_one = reference_case(&baseline.cases[1]);
    let changed_zero = reference_case(&changed_seed.cases[0]);

    assert_ne!(baseline_zero.inputs, baseline_one.inputs);
    assert_ne!(baseline_zero.context, baseline_one.context);
    assert_ne!(baseline_zero.inputs, changed_zero.inputs);
    assert_ne!(baseline_zero.context, changed_zero.context);
}

#[test]
fn corpus_size_is_bounded_and_nonzero() {
    assert_eq!(
        differential_vector_corpus_v1(PUBLIC_TEST_SEED, 0),
        Err(DifferentialVectorError::EmptyCorpus)
    );
    assert_eq!(
        differential_vector_corpus_v1(PUBLIC_TEST_SEED, MAX_DIFFERENTIAL_VECTOR_CASES_V1 + 1),
        Err(DifferentialVectorError::TooManyCases {
            requested: MAX_DIFFERENTIAL_VECTOR_CASES_V1 + 1,
            maximum: MAX_DIFFERENTIAL_VECTOR_CASES_V1,
        })
    );
}

fn reference_case(case: &VectorCaseV1) -> &ed25519_yao_generator::VectorReferenceCaseV1 {
    match case {
        VectorCaseV1::Registration(reference)
        | VectorCaseV1::Activation(reference)
        | VectorCaseV1::Recovery(reference)
        | VectorCaseV1::Refresh(reference) => reference,
        VectorCaseV1::Export(export) => &export.reference,
    }
}
