use router_ab_ecdsa_online::{
    compute_client_signature_share, finalize_signing_worker_signature, ClientPresignMaterial,
    OnlineClientInput, SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
};

#[test]
fn purpose_built_online_roles_match_pinned_near_oracle() {
    let group_public_key33 = [
        2, 254, 141, 30, 177, 188, 179, 67, 43, 29, 181, 131, 63, 245, 242, 34, 109, 156, 181, 230,
        92, 238, 67, 5, 88, 193, 142, 211, 163, 200, 108, 225, 175,
    ];
    let big_r33 = [
        3, 237, 150, 72, 69, 132, 153, 242, 148, 195, 128, 215, 84, 235, 17, 17, 182, 76, 107, 254,
        74, 146, 36, 62, 241, 41, 198, 185, 22, 109, 37, 77, 101,
    ];
    let client_k = [
        197, 87, 37, 100, 201, 71, 119, 15, 251, 24, 175, 179, 76, 165, 241, 88, 226, 144, 113, 32,
        42, 139, 246, 79, 67, 44, 131, 217, 172, 59, 26, 168,
    ];
    let client_sigma = [
        41, 80, 108, 245, 183, 251, 136, 226, 31, 123, 65, 156, 75, 13, 173, 79, 47, 134, 41, 97,
        244, 228, 59, 120, 19, 22, 222, 236, 92, 19, 78, 7,
    ];
    let worker_k = [
        25, 44, 47, 163, 99, 81, 14, 235, 214, 85, 18, 72, 234, 132, 84, 147, 108, 236, 231, 46,
        206, 85, 187, 156, 14, 32, 147, 195, 90, 217, 117, 188,
    ];
    let worker_sigma = [
        78, 198, 64, 113, 86, 175, 115, 21, 142, 26, 165, 65, 13, 115, 255, 14, 88, 0, 186, 239,
        201, 21, 93, 175, 190, 23, 137, 88, 64, 173, 14, 87,
    ];
    let digest32 = [0x42; 32];
    let entropy32 = [0x24; 32];

    let client_committed = ClientPresignMaterial::from_bytes(big_r33, client_k, client_sigma)
        .unwrap()
        .reserve()
        .commit(OnlineClientInput::new(group_public_key33, big_r33, digest32, entropy32).unwrap())
        .unwrap();
    let client_share = compute_client_signature_share(client_committed).unwrap();
    let oracle_client_share =
        signer_core::threshold_ecdsa::threshold_ecdsa_compute_signature_share(
            &[1, 2],
            1,
            &group_public_key33,
            &big_r33,
            &client_k,
            &client_sigma,
            &digest32,
            &entropy32,
        )
        .unwrap();
    assert_eq!(client_share.as_slice(), oracle_client_share);

    let worker_committed =
        SigningWorkerPresignMaterial::from_bytes(big_r33, worker_k, worker_sigma)
            .unwrap()
            .reserve()
            .commit(
                SigningWorkerOnlineInput::new(group_public_key33, big_r33, digest32, entropy32)
                    .unwrap(),
            )
            .unwrap();
    let signature = finalize_signing_worker_signature(worker_committed, client_share).unwrap();
    let oracle_signature = signer_core::threshold_ecdsa::threshold_ecdsa_finalize_signature(
        &[1, 2],
        2,
        &group_public_key33,
        &big_r33,
        &worker_k,
        &worker_sigma,
        &digest32,
        &entropy32,
        &oracle_client_share,
    )
    .unwrap();
    assert_eq!(signature.as_slice(), oracle_signature);
}
