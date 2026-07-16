pub mod error;
pub mod operation;

pub mod codec;
#[cfg(all(
    feature = "typescript-bindings",
    any(
        feature = "threshold-ecdsa",
        feature = "near-threshold-ed25519",
        feature = "ecdsa-role-local-client"
    )
))]
pub mod commands;
#[cfg(feature = "ecdsa-role-local-client")]
pub mod ecdsa_role_local_client;
#[cfg(feature = "ed25519-yao-derivation")]
pub mod ed25519_yao_derivation;
#[cfg(feature = "tx-finalization")]
pub mod eip1559;
#[cfg(feature = "near-crypto")]
pub mod near_crypto;
#[cfg(any(feature = "near-ed25519-recovery", feature = "near-threshold-ed25519"))]
pub mod near_ed25519_recovery;
#[cfg(feature = "near-threshold-ed25519")]
pub mod near_threshold_ed25519;
#[cfg(feature = "near-threshold-ed25519")]
pub mod near_threshold_frost;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;
#[cfg(feature = "tx-finalization")]
pub mod tempo_tx;
#[cfg(feature = "threshold-ecdsa")]
pub mod threshold_ecdsa;
#[cfg(feature = "webauthn-p256")]
pub mod webauthn_p256;

#[cfg(all(test, feature = "secp256k1", feature = "near-crypto"))]
mod platform_surface_tests {
    include!("../fixtures/signing-vectors/platform_surface_tests.rs");
}
