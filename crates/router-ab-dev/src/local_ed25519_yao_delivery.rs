use rand_core_09::{OsRng, TryRngCore};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1,
    RouterAbProtocolResult,
};
use zeroize::Zeroizing;

pub type LocalEd25519YaoRecipientKeyPairV1 = router_ab_ed25519_yao::Ed25519YaoRecipientKeyPairV1;
pub type LocalEd25519YaoRecipientPrivateKeyV1 =
    router_ab_ed25519_yao::Ed25519YaoRecipientPrivateKeyV1;

pub fn generate_local_ed25519_yao_recipient_key_pair_v1(
) -> RouterAbProtocolResult<LocalEd25519YaoRecipientKeyPairV1> {
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    router_ab_ed25519_yao::generate_ed25519_yao_recipient_key_pair_v1(&mut rng)
}

pub fn derive_local_ed25519_yao_recipient_key_pair_v1(
    input_key_material: &[u8],
) -> RouterAbProtocolResult<LocalEd25519YaoRecipientKeyPairV1> {
    router_ab_ed25519_yao::derive_ed25519_yao_recipient_key_pair_v1(input_key_material)
}

pub fn seal_local_ed25519_yao_package_v1(
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    recipient_public_key: [u8; 32],
    plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedPackageV1> {
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    router_ab_ed25519_yao::seal_ed25519_yao_package_v1(
        &mut rng,
        kind,
        deriver,
        session,
        transcript,
        recipient_public_key,
        plaintext,
    )
}

pub fn open_local_ed25519_yao_client_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    router_ab_ed25519_yao::open_ed25519_yao_client_package_v1(envelope, private_key)
}

pub fn open_local_ed25519_yao_signing_worker_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    router_ab_ed25519_yao::open_ed25519_yao_signing_worker_package_v1(envelope, private_key)
}
