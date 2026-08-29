use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootShareEpoch,
};

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("fixed tenant root identity")
}

#[test]
fn tenant_root_identity_canonical_bytes_and_digest_are_pinned() {
    let identity = identity();

    assert_eq!(
        hex::encode(identity.canonical_bytes().unwrap()),
        "7365616d732f74656e616e742d726f6f742d6964656e746974792f7631\
         000000056f72672d31\
         0000000970726f6a6563742d32\
         0000000a70726f64756374696f6e\
         00000009726f6f742d6d61696e\
         000000027633"
            .replace(char::is_whitespace, ""),
    );
    assert_eq!(
        hex::encode(identity.digest().unwrap().into_bytes()),
        "9c5d583ae4693793ce3b51590c788651ba0df4c2339b25b84676665fce44aa8b",
    );
    assert_eq!(identity.signing_root_id(), "root-main");
    assert_eq!(identity.signing_root_version(), "v3");
}

#[test]
fn tenant_root_identity_json_boundary_rejects_partial_unknown_and_empty_shapes() {
    let encoded = serde_json::to_string(&identity()).unwrap();
    let decoded: TenantRootIdentityV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, identity());

    let missing = r#"{
        "orgId":"org-1",
        "projectId":"project-2",
        "envId":"production",
        "signingRootId":"root-main"
    }"#;
    assert!(serde_json::from_str::<TenantRootIdentityV1>(missing).is_err());

    let unknown = r#"{
        "orgId":"org-1",
        "projectId":"project-2",
        "envId":"production",
        "signingRootId":"root-main",
        "signingRootVersion":"v3",
        "rootShareEpoch":1
    }"#;
    assert!(serde_json::from_str::<TenantRootIdentityV1>(unknown).is_err());

    let empty =
        TenantRootIdentityV1::new("", "project-2", "production", "root-main", "v3").unwrap_err();
    assert_eq!(empty.code(), RouterAbDerivationErrorCode::EmptyField);
}

#[test]
fn custody_lineage_uses_exact_nonzero_unpadded_base64url() {
    let lineage = TenantRootCustodyLineageId::from_bytes([0xa5; 16]).unwrap();
    assert_eq!(lineage.to_base64url(), "paWlpaWlpaWlpaWlpaWlpQ");
    assert_eq!(
        TenantRootCustodyLineageId::from_base64url("paWlpaWlpaWlpaWlpaWlpQ").unwrap(),
        lineage,
    );
    assert!(TenantRootCustodyLineageId::from_base64url("paWlpaWlpaWlpaWlpaWlpQ==").is_err());
    assert!(TenantRootCustodyLineageId::from_base64url("paWlpaWlpaWlpaWlpaWl").is_err());
    assert!(TenantRootCustodyLineageId::from_bytes([0_u8; 16]).is_err());

    let encoded = serde_json::to_string(&lineage).unwrap();
    assert_eq!(encoded, r#""paWlpaWlpaWlpaWlpaWlpQ""#);
    assert_eq!(
        serde_json::from_str::<TenantRootCustodyLineageId>(&encoded).unwrap(),
        lineage,
    );
}

#[test]
fn tenant_root_share_epoch_is_positive_exactly_monotonic_and_bounded() {
    assert_eq!(TenantRootShareEpoch::INITIAL.get().get(), 1);
    assert_eq!(TenantRootShareEpoch::INITIAL.next().unwrap().get().get(), 2);
    assert!(TenantRootShareEpoch::new(0).is_err());
    assert!(TenantRootShareEpoch::new(u64::MAX).unwrap().next().is_err());
    assert_eq!(
        serde_json::from_str::<TenantRootShareEpoch>("7")
            .unwrap()
            .get()
            .get(),
        7,
    );
    assert!(serde_json::from_str::<TenantRootShareEpoch>("0").is_err());
}
