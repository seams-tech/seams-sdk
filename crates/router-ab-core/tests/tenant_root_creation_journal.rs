use router_ab_core::{
    rebuild_tenant_root_creation_state_v1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCreationJournalV1, TenantRootCreationStateV1,
    TenantRootCustodyLineageId, TenantRootEmptyCreationV1, TenantRootIdentityV1,
    TenantRootShareEpoch, TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1,
};
use sha2::{Digest, Sha256};

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("fixed tenant-root identity")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("fixed custody lineage")
}

fn creation_context(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_seed: u8,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity.digest().expect("identity digest"),
        custody_lineage,
        TenantRootCeremonyEpochsV1::create(),
        router_ab_core::TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16])
            .expect("fixed session id"),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).expect("fixed ceremony nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("fixed creation context")
}

fn refresh_context(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity.digest().expect("identity digest"),
        custody_lineage,
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(3).expect("current epoch"),
            TenantRootShareEpoch::new(4).expect("next epoch"),
        )
        .expect("one-step refresh"),
        router_ab_core::TenantRootCeremonySessionIdV1::from_bytes([0x22; 16])
            .expect("fixed session id"),
        TenantRootCeremonyNonceV1::from_bytes([0x42; 32]).expect("fixed ceremony nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("fixed refresh context")
}

fn journal() -> TenantRootCreationJournalV1 {
    let identity = identity();
    TenantRootCreationJournalV1::started(
        identity.clone(),
        lineage(0x31),
        creation_context(&identity, lineage(0x31), 0x21),
    )
    .expect("fixed Started journal")
}

fn field_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let start = offset + 4;
        ranges.push(start..start + length);
        offset = start + length;
    }
    assert_eq!(offset, bytes.len());
    ranges
}

#[test]
fn started_round_trips_with_genesis_scope_and_event_digest() {
    let identity = identity();
    let custody_lineage = lineage(0x31);
    let context = creation_context(&identity, custody_lineage, 0x21);
    let journal =
        TenantRootCreationJournalV1::started(identity.clone(), custody_lineage, context.clone())
            .unwrap();
    let bytes = journal.canonical_bytes().unwrap();
    let fields = field_ranges(&bytes);

    assert_eq!(journal.revision(), 1);
    assert_eq!(journal.identity_digest(), identity.digest().unwrap());
    assert_eq!(journal.custody_lineage(), custody_lineage);
    assert_eq!(
        &bytes[fields[0].clone()],
        b"seams/tenant-root-creation-event/v1"
    );
    assert_eq!(&bytes[fields[1].clone()], &1_u64.to_be_bytes());
    assert_eq!(&bytes[fields[2].clone()], &[0_u8; 32]);
    assert_eq!(
        &bytes[fields[3].clone()],
        identity.digest().unwrap().as_bytes(),
    );
    assert_eq!(&bytes[fields[4].clone()], custody_lineage.as_bytes());
    assert_eq!(&bytes[fields[5].clone()], b"started");

    let decoded = TenantRootCreationJournalV1::decode_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, journal);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(decoded.digest().unwrap().into_bytes(), expected_digest);

    let started = match &decoded {
        TenantRootCreationJournalV1::Started(event) => event,
    };
    assert_eq!(
        started.identity_canonical_bytes(),
        &identity.canonical_bytes().unwrap()
    );
    assert_eq!(
        started.ceremony_context_canonical_bytes(),
        &context.canonical_bytes().unwrap()
    );
}

#[test]
fn started_rebuilds_exact_preparing_state_from_canonical_bytes() {
    let identity = identity();
    let custody_lineage = lineage(0x31);
    let context = creation_context(&identity, custody_lineage, 0x21);
    let journal =
        TenantRootCreationJournalV1::started(identity.clone(), custody_lineage, context.clone())
            .unwrap();
    let bytes = journal.canonical_bytes().unwrap();
    let decoded = TenantRootCreationJournalV1::decode_canonical_bytes(&bytes).unwrap();

    let expected = TenantRootCreationStateV1::Preparing(
        TenantRootEmptyCreationV1::new(identity.clone(), custody_lineage)
            .start(&context)
            .unwrap(),
    );
    assert_eq!(
        decoded.rebuild(identity.clone(), custody_lineage).unwrap(),
        expected
    );
    assert_eq!(
        rebuild_tenant_root_creation_state_v1(&bytes, identity, custody_lineage).unwrap(),
        expected
    );
}

#[test]
fn started_rejects_tampering_trailing_bytes_and_oversize_wires() {
    let bytes = journal().canonical_bytes().unwrap();
    let fields = field_ranges(&bytes);

    for field_index in [0, 1, 2, 3, 4, 5] {
        let mut tampered = bytes.clone();
        tampered[fields[field_index].start] ^= 1;
        assert!(
            TenantRootCreationJournalV1::decode_canonical_bytes(&tampered).is_err(),
            "field {field_index} must be authenticated"
        );
    }

    let mut tampered_payload = bytes.clone();
    let payload_range = fields[6].clone();
    let payload_fields = field_ranges(&bytes[payload_range.clone()]);
    let context_byte = payload_range.start + payload_fields[1].start;
    tampered_payload[context_byte] ^= 1;
    assert!(TenantRootCreationJournalV1::decode_canonical_bytes(&tampered_payload).is_err());

    let mut empty_tag = bytes.clone();
    let tag_length_offset = fields[5].start - 4;
    empty_tag[tag_length_offset..tag_length_offset + 4].fill(0);
    assert!(TenantRootCreationJournalV1::decode_canonical_bytes(&empty_tag).is_err());

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootCreationJournalV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootCreationJournalV1::decode_canonical_bytes(&bytes[..bytes.len() - 1]).is_err()
    );
    assert!(TenantRootCreationJournalV1::decode_canonical_bytes(&[]).is_err());
    assert!(TenantRootCreationJournalV1::decode_canonical_bytes(&vec![
        0_u8;
        TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1
            + 1
    ])
    .is_err());
}

#[test]
fn started_rejects_identity_lineage_and_refresh_context_substitution() {
    let identity = identity();
    let custody_lineage = lineage(0x31);
    let journal = TenantRootCreationJournalV1::started(
        identity.clone(),
        custody_lineage,
        creation_context(&identity, custody_lineage, 0x21),
    )
    .unwrap();

    let other_identity =
        TenantRootIdentityV1::new("org-2", "project-2", "production", "root-main", "v3").unwrap();
    assert!(journal.rebuild(other_identity, custody_lineage).is_err());
    assert!(journal.rebuild(identity.clone(), lineage(0x32)).is_err());

    let refresh = refresh_context(&identity, custody_lineage);
    assert!(TenantRootCreationJournalV1::started(identity, custody_lineage, refresh).is_err());
}

#[test]
fn started_replay_is_exact_and_context_changes_are_digest_bound() {
    let identity = identity();
    let custody_lineage = lineage(0x31);
    let first = TenantRootCreationJournalV1::started(
        identity.clone(),
        custody_lineage,
        creation_context(&identity, custody_lineage, 0x21),
    )
    .unwrap();
    let same = TenantRootCreationJournalV1::started(
        identity.clone(),
        custody_lineage,
        creation_context(&identity, custody_lineage, 0x21),
    )
    .unwrap();
    let different_context = TenantRootCreationJournalV1::started(
        identity.clone(),
        custody_lineage,
        creation_context(&identity, custody_lineage, 0x22),
    )
    .unwrap();

    assert_eq!(first, same);
    assert_eq!(
        first.canonical_bytes().unwrap(),
        same.canonical_bytes().unwrap()
    );
    assert_eq!(first.digest().unwrap(), same.digest().unwrap());
    assert_ne!(
        first.canonical_bytes().unwrap(),
        different_context.canonical_bytes().unwrap()
    );
    assert_ne!(first.digest().unwrap(), different_context.digest().unwrap());
}
