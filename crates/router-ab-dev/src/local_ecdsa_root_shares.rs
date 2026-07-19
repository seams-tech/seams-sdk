use rand_core::{CryptoRng, Error as RandError, RngCore};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use sha2::{Digest, Sha256};
use threshold_prf::{
    generate_signing_root, split_signing_root, SigningRootShareWire, ThresholdPolicy,
};

use crate::local_generated_secret_bytes_v1;

/// Deterministically generated local Deriver root-share material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEcdsaRootSharePackageV1 {
    /// Deriver A root-share wire secret.
    pub deriver_a_root_share_wire_secret: String,
    /// Deriver B root-share wire secret.
    pub deriver_b_root_share_wire_secret: String,
}

/// Generates the fixed two-of-two local ECDSA root-share package.
pub fn local_ecdsa_root_share_package_v1(
    seed: &[u8],
) -> RouterAbProtocolResult<LocalEcdsaRootSharePackageV1> {
    let mut rng = DeterministicRootShareRng::new(seed)?;
    let root = generate_signing_root(&mut rng);
    let threshold = ThresholdPolicy::from_u16s(2, 2).map_err(root_share_error)?;
    let shares = split_signing_root(&root, threshold, &mut rng).map_err(root_share_error)?;
    let share_a = SigningRootShareWire::from_share(&shares[0]).to_bytes();
    let share_b = SigningRootShareWire::from_share(&shares[1]).to_bytes();
    Ok(LocalEcdsaRootSharePackageV1 {
        deriver_a_root_share_wire_secret: wire_secret(&share_a),
        deriver_b_root_share_wire_secret: wire_secret(&share_b),
    })
}

fn wire_secret(bytes: &[u8; 34]) -> String {
    format!("mpc-prf-root-share-wire-v1:{}", hex::encode(bytes))
}

fn root_share_error(error: impl core::fmt::Debug) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ECDSA root-share generation failed: {error:?}"),
    )
}

struct DeterministicRootShareRng {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    offset: usize,
}

impl DeterministicRootShareRng {
    fn new(seed: &[u8]) -> RouterAbProtocolResult<Self> {
        Ok(Self {
            seed: local_generated_secret_bytes_v1("threshold-prf-root", seed)?,
            counter: 0,
            buffer: [0u8; 32],
            offset: 32,
        })
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"router-ab-dev/ecdsa-root-share-rng/v1");
        hasher.update(self.seed);
        hasher.update(self.counter.to_be_bytes());
        self.buffer = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
}

impl RngCore for DeterministicRootShareRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.offset];
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for DeterministicRootShareRng {}
