use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use router_ab_core::{
    ed25519_yao_encrypted_input_digest_v1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoInputPairBindingV1, Ed25519YaoRoleReadinessReceiptV1,
    Ed25519YaoRoleSignatureSchemeV1, Ed25519YaoSessionIdV1, PublicDigest32, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use router_ab_ed25519_yao::Ed25519YaoRoleExecutionV1;
use serde::{Deserialize, Serialize};

const READINESS_SIGNATURE_DIGEST_PLACEHOLDER: [u8; 64] = [1_u8; 64];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalEd25519YaoPairLifecycleStateV1 {
    Prepared {
        pair_digest: [u8; 32],
        deriver_a: LocalEd25519YaoRoleReadinessReceiptV1,
        deriver_b: LocalEd25519YaoRoleReadinessReceiptV1,
    },
    Running {
        pair_digest: [u8; 32],
    },
    Expired {
        pair_digest: [u8; 32],
    },
    Completed {
        pair_digest: [u8; 32],
        deriver_a: Box<Ed25519YaoRoleExecutionV1>,
        deriver_b: Box<Ed25519YaoRoleExecutionV1>,
    },
    Burned {
        pair_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRoleReadinessReceiptV1 {
    pub receipt: Ed25519YaoRoleReadinessReceiptV1,
    pub input_digest: [u8; 32],
    pub root_metadata_digest: [u8; 32],
}

/// Role-specific signing keys used by the local pair harness.
///
/// Keeping both keys in the coordinator prevents the local adapter from
/// accidentally signing a Deriver B receipt with Deriver A's key when the
/// second role arrives first.
#[derive(Debug, Clone, Copy)]
pub struct LocalEd25519YaoPairSigningKeysV1 {
    pub deriver_a: [u8; 32],
    pub deriver_b: [u8; 32],
}

#[derive(Debug, Default, Clone)]
pub struct LocalEd25519YaoPairLifecycleV1 {
    state: Option<LocalEd25519YaoPairLifecycleStateV1>,
    prepared_pair_digest: Option<[u8; 32]>,
    prepared_receipts: [Option<LocalEd25519YaoRoleReadinessReceiptV1>; 2],
}

/// Durable representation of one local pair lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoPairLifecycleSnapshotV1 {
    /// Current lifecycle state, when both roles have prepared.
    pub state: Option<LocalEd25519YaoPairLifecycleStateV1>,
    /// Pair identity recorded by the first role to prepare.
    pub prepared_pair_digest: Option<[u8; 32]>,
    /// Role-specific preparation records, indexed A then B.
    pub prepared_receipts: [Option<LocalEd25519YaoRoleReadinessReceiptV1>; 2],
}

impl LocalEd25519YaoPairLifecycleV1 {
    /// Returns a serializable copy of this lifecycle.
    pub fn snapshot(&self) -> LocalEd25519YaoPairLifecycleSnapshotV1 {
        LocalEd25519YaoPairLifecycleSnapshotV1 {
            state: self.state.clone(),
            prepared_pair_digest: self.prepared_pair_digest,
            prepared_receipts: self.prepared_receipts.clone(),
        }
    }

    /// Restores a lifecycle from a persisted snapshot after checking invariants.
    pub fn from_snapshot(
        snapshot: LocalEd25519YaoPairLifecycleSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_snapshot(&snapshot)?;
        Ok(Self {
            state: snapshot.state,
            prepared_pair_digest: snapshot.prepared_pair_digest,
            prepared_receipts: snapshot.prepared_receipts,
        })
    }

    pub fn state(&self) -> Option<&LocalEd25519YaoPairLifecycleStateV1> {
        self.state.as_ref()
    }

    pub fn prepare_role(
        &mut self,
        role: Ed25519YaoDeriverRoleV1,
        pair: &Ed25519YaoInputPairBindingV1,
        input: Ed25519YaoEncryptedInputV1,
        root_metadata_digest: [u8; 32],
        prepared_at_ms: u64,
        expires_at_ms: u64,
        signing_keys: LocalEd25519YaoPairSigningKeysV1,
    ) -> RouterAbProtocolResult<Ed25519YaoRoleReadinessReceiptV1> {
        pair.validate()?;
        input.validate()?;
        let expected_kind = match pair.binding().operation.circuit_family() {
            router_ab_core::Ed25519YaoCircuitFamilyV1::Activation => {
                router_ab_core::Ed25519YaoInputKindV1::Activation
            }
            router_ab_core::Ed25519YaoCircuitFamilyV1::Export => {
                router_ab_core::Ed25519YaoInputKindV1::Export
            }
            router_ab_core::Ed25519YaoCircuitFamilyV1::LaneMaterialization => {
                router_ab_core::Ed25519YaoInputKindV1::LaneMaterialization
            }
        };
        if input.kind() != expected_kind {
            return Err(pair_lifecycle_error(
                "role input kind does not match the pair operation",
            ));
        }
        if input.deriver() != role || input.session() != pair.session() {
            return Err(pair_lifecycle_error("role input does not match the pair"));
        }
        let input_digest = ed25519_yao_encrypted_input_digest_v1(&input)?.bytes;
        let expected_input_digest = match role {
            Ed25519YaoDeriverRoleV1::DeriverA => pair.deriver_a_input_digest().bytes,
            Ed25519YaoDeriverRoleV1::DeriverB => pair.deriver_b_input_digest().bytes,
        };
        if input_digest != expected_input_digest {
            return Err(pair_lifecycle_error(
                "role input digest does not match the pair",
            ));
        }
        let slot = role_slot(role);
        if root_metadata_digest.iter().all(|byte| *byte == 0) {
            return Err(pair_lifecycle_error("root metadata digest must be nonzero"));
        }
        let pair_digest = pair.pair_digest().bytes;
        if let Some(stored_pair_digest) = self.prepared_pair_digest {
            if stored_pair_digest != pair_digest {
                return Err(pair_lifecycle_error("conflicting pair preparation"));
            }
        }
        match self.state.as_ref() {
            None => {}
            Some(LocalEd25519YaoPairLifecycleStateV1::Prepared {
                pair_digest: stored_pair_digest,
                ..
            }) if *stored_pair_digest == pair_digest => {
                return self
                    .prepared_receipt_for_role(role)
                    .filter(|stored| {
                        stored.input_digest == input_digest
                            && stored.root_metadata_digest == root_metadata_digest
                            && prepared_at_ms < stored.receipt.expires_at_ms()
                    })
                    .map(|stored| stored.receipt.clone())
                    .ok_or_else(|| pair_lifecycle_error("pair preparation is expired"));
            }
            Some(LocalEd25519YaoPairLifecycleStateV1::Expired { .. }) => {
                return Err(pair_lifecycle_error("pair lifecycle is terminal"));
            }
            Some(_) => return Err(pair_lifecycle_error("pair lifecycle is already committed")),
        }
        if let Some(existing) = self.prepared_receipts[slot].as_ref() {
            if existing.input_digest != input_digest
                || existing.root_metadata_digest != root_metadata_digest
            {
                return Err(pair_lifecycle_error("conflicting pair preparation"));
            }
            return Ok(existing.receipt.clone());
        }
        let signing_key = signing_key_for_role(role, signing_keys);
        let receipt = sign_receipt(
            role,
            pair,
            input_digest,
            root_metadata_digest,
            prepared_at_ms,
            expires_at_ms,
            signing_key,
        )?;
        self.prepared_pair_digest = Some(pair_digest);
        self.prepared_receipts[slot] = Some(LocalEd25519YaoRoleReadinessReceiptV1 {
            receipt: receipt.clone(),
            input_digest,
            root_metadata_digest,
        });
        if let (Some(deriver_a), Some(deriver_b)) = (
            self.prepared_receipts[0].as_ref(),
            self.prepared_receipts[1].as_ref(),
        ) {
            self.state = Some(LocalEd25519YaoPairLifecycleStateV1::Prepared {
                pair_digest,
                deriver_a: deriver_a.clone(),
                deriver_b: deriver_b.clone(),
            });
        }
        Ok(receipt)
    }

    fn prepared_receipt_for_role(
        &self,
        role: Ed25519YaoDeriverRoleV1,
    ) -> Option<&LocalEd25519YaoRoleReadinessReceiptV1> {
        self.prepared_receipts[role_slot(role)].as_ref()
    }

    pub fn begin(
        &mut self,
        pair: &Ed25519YaoInputPairBindingV1,
        deriver_a: &Ed25519YaoRoleReadinessReceiptV1,
        deriver_b: &Ed25519YaoRoleReadinessReceiptV1,
        deriver_a_verifying_key: [u8; 32],
        deriver_b_verifying_key: [u8; 32],
        now_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        deriver_a.validate_for_pair(pair)?;
        deriver_b.validate_for_pair(pair)?;
        let pair_digest = pair.pair_digest().bytes;
        if deriver_a.expires_at_ms() <= now_ms || deriver_b.expires_at_ms() <= now_ms {
            self.state = Some(LocalEd25519YaoPairLifecycleStateV1::Expired { pair_digest });
            return Err(pair_lifecycle_error("pair preparation is expired"));
        }
        deriver_a.validate_at(now_ms)?;
        deriver_b.validate_at(now_ms)?;
        verify_receipt(deriver_a, deriver_a_verifying_key)?;
        verify_receipt(deriver_b, deriver_b_verifying_key)?;
        match self.state.as_ref() {
            Some(LocalEd25519YaoPairLifecycleStateV1::Prepared {
                pair_digest: stored_pair_digest,
                deriver_a: stored_a,
                deriver_b: stored_b,
            }) if *stored_pair_digest == pair_digest
                && receipts_match_v1(stored_a, stored_b, deriver_a, deriver_b) =>
            {
                self.state = Some(LocalEd25519YaoPairLifecycleStateV1::Running { pair_digest });
                Ok(())
            }
            Some(LocalEd25519YaoPairLifecycleStateV1::Running {
                pair_digest: stored_pair_digest,
            }) if *stored_pair_digest == pair_digest => {
                let Some(stored_a) = self.prepared_receipts[0].as_ref() else {
                    return Err(pair_lifecycle_error("stored Deriver A receipt is missing"));
                };
                let Some(stored_b) = self.prepared_receipts[1].as_ref() else {
                    return Err(pair_lifecycle_error("stored Deriver B receipt is missing"));
                };
                if receipts_match_v1(stored_a, stored_b, deriver_a, deriver_b) {
                    Ok(())
                } else {
                    Err(pair_lifecycle_error(
                        "pair receipts do not match preparation",
                    ))
                }
            }
            Some(LocalEd25519YaoPairLifecycleStateV1::Expired {
                pair_digest: stored_pair_digest,
            }) if *stored_pair_digest == pair_digest => {
                Err(pair_lifecycle_error("pair lifecycle is terminal"))
            }
            _ => Err(pair_lifecycle_error(
                "pair execution requires exact prepared receipts",
            )),
        }
    }

    pub fn complete(
        &mut self,
        pair: &Ed25519YaoInputPairBindingV1,
        deriver_a: Ed25519YaoRoleExecutionV1,
        deriver_b: Ed25519YaoRoleExecutionV1,
    ) -> RouterAbProtocolResult<()> {
        pair.validate()?;
        if deriver_a.session() != pair.session() || deriver_b.session() != pair.session() {
            return Err(pair_lifecycle_error(
                "completed role session differs from the pair",
            ));
        }
        deriver_a.validate()?;
        deriver_b.validate()?;
        if deriver_a.deriver() != Ed25519YaoDeriverRoleV1::DeriverA
            || deriver_b.deriver() != Ed25519YaoDeriverRoleV1::DeriverB
        {
            return Err(pair_lifecycle_error(
                "completed role order does not match the pair",
            ));
        }
        match self.state.as_ref() {
            Some(LocalEd25519YaoPairLifecycleStateV1::Running { pair_digest })
                if *pair_digest == pair.pair_digest().bytes =>
            {
                self.state = Some(LocalEd25519YaoPairLifecycleStateV1::Completed {
                    pair_digest: *pair_digest,
                    deriver_a: Box::new(deriver_a),
                    deriver_b: Box::new(deriver_b),
                });
                Ok(())
            }
            Some(LocalEd25519YaoPairLifecycleStateV1::Completed {
                pair_digest: stored_pair_digest,
                deriver_a: stored_a,
                deriver_b: stored_b,
            }) if *stored_pair_digest == pair.pair_digest().bytes
                && **stored_a == deriver_a
                && **stored_b == deriver_b =>
            {
                Ok(())
            }
            _ => Err(pair_lifecycle_error(
                "pair completion requires Running state",
            )),
        }
    }

    pub fn burn(&mut self, pair_digest: [u8; 32]) -> RouterAbProtocolResult<()> {
        match self.state.as_ref() {
            Some(LocalEd25519YaoPairLifecycleStateV1::Running {
                pair_digest: stored_pair,
            }) if *stored_pair == pair_digest => {
                self.state = Some(LocalEd25519YaoPairLifecycleStateV1::Burned { pair_digest });
                Ok(())
            }
            Some(LocalEd25519YaoPairLifecycleStateV1::Burned {
                pair_digest: stored_pair,
            }) if *stored_pair == pair_digest => Ok(()),
            _ => Err(pair_lifecycle_error("only a running pair can be burned")),
        }
    }

    pub fn completed(
        &self,
        pair_digest: [u8; 32],
    ) -> RouterAbProtocolResult<(&Ed25519YaoRoleExecutionV1, &Ed25519YaoRoleExecutionV1)> {
        match self.state.as_ref() {
            Some(LocalEd25519YaoPairLifecycleStateV1::Completed {
                pair_digest: stored_pair,
                deriver_a,
                deriver_b,
            }) if *stored_pair == pair_digest => Ok((deriver_a, deriver_b)),
            _ => Err(pair_lifecycle_error("pair has no exact completed output")),
        }
    }
}

fn sign_receipt(
    role: Ed25519YaoDeriverRoleV1,
    pair: &Ed25519YaoInputPairBindingV1,
    input_digest: [u8; 32],
    root_metadata_digest: [u8; 32],
    prepared_at_ms: u64,
    expires_at_ms: u64,
    signing_key: [u8; 32],
) -> RouterAbProtocolResult<Ed25519YaoRoleReadinessReceiptV1> {
    let session = Ed25519YaoSessionIdV1::new(pair.session())?;
    let placeholder = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        READINESS_SIGNATURE_DIGEST_PLACEHOLDER,
    )?;
    let unsigned = Ed25519YaoRoleReadinessReceiptV1::new(
        role,
        session,
        PublicDigest32::new(pair.pair_digest().bytes),
        PublicDigest32::new(input_digest),
        PublicDigest32::new(root_metadata_digest),
        prepared_at_ms,
        expires_at_ms,
        placeholder,
    )?;
    let key = SigningKey::from_bytes(&signing_key);
    let signature = key
        .sign(unsigned.signed_message_digest().as_bytes())
        .to_bytes();
    let signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        signature,
    )?;
    Ed25519YaoRoleReadinessReceiptV1::new(
        role,
        session,
        PublicDigest32::new(pair.pair_digest().bytes),
        PublicDigest32::new(input_digest),
        PublicDigest32::new(root_metadata_digest),
        prepared_at_ms,
        expires_at_ms,
        signature,
    )
}

fn verify_receipt(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    verifying_key: [u8; 32],
) -> RouterAbProtocolResult<()> {
    let verifying_key = VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| pair_lifecycle_error("readiness verifying key is malformed"))?;
    let signature = Signature::from_slice(receipt.signature().bytes())
        .map_err(|_| pair_lifecycle_error("readiness signature is malformed"))?;
    verifying_key
        .verify(receipt.signed_message_digest().as_bytes(), &signature)
        .map_err(|_| pair_lifecycle_error("readiness signature is invalid"))
}

pub(crate) fn verify_local_pair_readiness_receipt_v1(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    verifying_key: [u8; 32],
) -> RouterAbProtocolResult<()> {
    verify_receipt(receipt, verifying_key)
}

fn role_slot(role: Ed25519YaoDeriverRoleV1) -> usize {
    match role {
        Ed25519YaoDeriverRoleV1::DeriverA => 0,
        Ed25519YaoDeriverRoleV1::DeriverB => 1,
    }
}

fn signing_key_for_role(
    role: Ed25519YaoDeriverRoleV1,
    signing_keys: LocalEd25519YaoPairSigningKeysV1,
) -> [u8; 32] {
    match role {
        Ed25519YaoDeriverRoleV1::DeriverA => signing_keys.deriver_a,
        Ed25519YaoDeriverRoleV1::DeriverB => signing_keys.deriver_b,
    }
}

fn receipts_match_v1(
    stored_a: &LocalEd25519YaoRoleReadinessReceiptV1,
    stored_b: &LocalEd25519YaoRoleReadinessReceiptV1,
    deriver_a: &Ed25519YaoRoleReadinessReceiptV1,
    deriver_b: &Ed25519YaoRoleReadinessReceiptV1,
) -> bool {
    stored_a.receipt == *deriver_a
        && stored_b.receipt == *deriver_b
        && stored_a.root_metadata_digest == deriver_a.root_metadata_digest().bytes
        && stored_b.root_metadata_digest == deriver_b.root_metadata_digest().bytes
}

fn pair_lifecycle_error(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

fn validate_snapshot(
    snapshot: &LocalEd25519YaoPairLifecycleSnapshotV1,
) -> RouterAbProtocolResult<()> {
    if snapshot.prepared_pair_digest.is_none()
        && (snapshot.state.is_some() || snapshot.prepared_receipts.iter().any(Option::is_some))
    {
        return Err(pair_lifecycle_error(
            "pair lifecycle snapshot has state without a prepared pair digest",
        ));
    }
    if snapshot.state.is_none()
        && snapshot.prepared_pair_digest.is_some()
        && snapshot.prepared_receipts.iter().all(Option::is_none)
    {
        return Err(pair_lifecycle_error(
            "pair lifecycle snapshot has a pair digest without a preparation record",
        ));
    }
    for (slot, prepared) in snapshot.prepared_receipts.iter().enumerate() {
        let Some(prepared) = prepared else {
            continue;
        };
        let expected_role = if slot == 0 {
            Ed25519YaoDeriverRoleV1::DeriverA
        } else {
            Ed25519YaoDeriverRoleV1::DeriverB
        };
        if prepared.receipt.role() != expected_role
            || prepared.input_digest != prepared.receipt.local_input_digest().bytes
            || prepared.root_metadata_digest != prepared.receipt.root_metadata_digest().bytes
        {
            return Err(pair_lifecycle_error(
                "pair lifecycle snapshot has an inconsistent preparation record",
            ));
        }
        let Some(pair_digest) = snapshot.prepared_pair_digest else {
            return Err(pair_lifecycle_error(
                "pair lifecycle snapshot is missing the prepared pair digest",
            ));
        };
        if prepared.receipt.pair_digest().bytes != pair_digest {
            return Err(pair_lifecycle_error(
                "pair lifecycle snapshot receipt has the wrong pair digest",
            ));
        }
    }

    if let Some(state) = snapshot.state.as_ref() {
        let state_pair_digest = match state {
            LocalEd25519YaoPairLifecycleStateV1::Prepared { pair_digest, .. }
            | LocalEd25519YaoPairLifecycleStateV1::Running { pair_digest }
            | LocalEd25519YaoPairLifecycleStateV1::Expired { pair_digest }
            | LocalEd25519YaoPairLifecycleStateV1::Burned { pair_digest }
            | LocalEd25519YaoPairLifecycleStateV1::Completed { pair_digest, .. } => *pair_digest,
        };
        if state_pair_digest.iter().all(|byte| *byte == 0)
            || snapshot.prepared_pair_digest != Some(state_pair_digest)
        {
            return Err(pair_lifecycle_error(
                "pair lifecycle snapshot state has the wrong pair digest",
            ));
        }
        match state {
            LocalEd25519YaoPairLifecycleStateV1::Prepared {
                deriver_a,
                deriver_b,
                ..
            } => {
                if snapshot.prepared_receipts[0].as_ref() != Some(deriver_a)
                    || snapshot.prepared_receipts[1].as_ref() != Some(deriver_b)
                {
                    return Err(pair_lifecycle_error(
                        "pair lifecycle snapshot is missing a prepared receipt",
                    ));
                }
            }
            LocalEd25519YaoPairLifecycleStateV1::Completed {
                deriver_a,
                deriver_b,
                ..
            } => {
                deriver_a.validate()?;
                deriver_b.validate()?;
                if deriver_a.deriver() != Ed25519YaoDeriverRoleV1::DeriverA
                    || deriver_b.deriver() != Ed25519YaoDeriverRoleV1::DeriverB
                    || deriver_a.session() != deriver_b.session()
                {
                    return Err(pair_lifecycle_error(
                        "pair lifecycle snapshot has invalid completed role outputs",
                    ));
                }
            }
            LocalEd25519YaoPairLifecycleStateV1::Running { .. }
            | LocalEd25519YaoPairLifecycleStateV1::Expired { .. }
            | LocalEd25519YaoPairLifecycleStateV1::Burned { .. } => {
                if snapshot.prepared_receipts.iter().any(Option::is_none) {
                    return Err(pair_lifecycle_error(
                        "pair lifecycle snapshot is missing a receipt for its committed state",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoCeremonyBindingV1, Ed25519YaoCeremonyIdentityV1, Ed25519YaoEncryptedPackageV1,
        Ed25519YaoInputKindV1, Ed25519YaoOperationV1, Ed25519YaoPackageKindV1,
        Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1,
        MpcMaterialActivationRefV1, RootShareEpoch,
    };

    fn pair_fixture() -> (
        Ed25519YaoInputPairBindingV1,
        Ed25519YaoEncryptedInputV1,
        Ed25519YaoEncryptedInputV1,
    ) {
        let lifecycle = LifecycleScopeV1::new(
            "local-pair-lifecycle",
            ExpensiveWorkKindV1::RegistrationPrepare,
            RootShareEpoch::new("local-root-epoch").expect("root epoch"),
            "local-account",
            "local-wallet-session",
            "local-signer-set",
            "local-signing-worker",
        )
        .expect("lifecycle");
        let ceremony_binding = Ed25519YaoCeremonyBindingV1::new(
            lifecycle,
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([0x51; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([0x61; 32]),
            MpcMaterialActivationRefV1::new(
                "pair-activation",
                "pair-capability",
                "local-account",
                "pair-key",
                "local-pair-lifecycle",
                "local-signing-worker",
            )
            .expect("material activation"),
        )
        .expect("ceremony binding");
        let input_a = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            [0x51; 32],
            [0x61; 32],
            [0x81; 32],
            vec![0x91; 16],
        )
        .expect("Deriver A input");
        let input_b = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            [0x51; 32],
            [0x61; 32],
            [0x82; 32],
            vec![0x92; 16],
        )
        .expect("Deriver B input");
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(ceremony_binding)
            .expect("ceremony identity");
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &input_a,
            &input_b,
            PublicDigest32::new([0xa1; 32]),
            PublicDigest32::new([0xb1; 32]),
        )
        .expect("pair binding");
        (pair, input_a, input_b)
    }

    fn signing_keys() -> (LocalEd25519YaoPairSigningKeysV1, [u8; 32], [u8; 32]) {
        let deriver_a = SigningKey::from_bytes(&[0x11; 32]);
        let deriver_b = SigningKey::from_bytes(&[0x22; 32]);
        (
            LocalEd25519YaoPairSigningKeysV1 {
                deriver_a: [0x11; 32],
                deriver_b: [0x22; 32],
            },
            deriver_a.verifying_key().to_bytes(),
            deriver_b.verifying_key().to_bytes(),
        )
    }

    #[test]
    fn pair_lifecycle_snapshot_round_trips_prepared_state() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, _, _) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc1; 32],
                1,
                100,
                signing_keys,
            )
            .expect("Deriver A preparation");
        lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc2; 32],
                2,
                100,
                signing_keys,
            )
            .expect("Deriver B preparation");

        let snapshot = lifecycle.snapshot();
        let encoded = serde_json::to_vec(&snapshot).expect("snapshot JSON");
        let decoded: LocalEd25519YaoPairLifecycleSnapshotV1 =
            serde_json::from_slice(&encoded).expect("snapshot JSON decode");
        let restored = LocalEd25519YaoPairLifecycleV1::from_snapshot(decoded)
            .expect("prepared snapshot should restore");
        assert_eq!(restored.snapshot(), snapshot);
    }

    #[test]
    fn pair_lifecycle_snapshot_rejects_inconsistent_state() {
        let (pair, input_a, _) = pair_fixture();
        let (signing_keys, _, _) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc1; 32],
                1,
                100,
                signing_keys,
            )
            .expect("Deriver A preparation");
        let mut snapshot = lifecycle.snapshot();
        snapshot.prepared_pair_digest = None;
        assert!(LocalEd25519YaoPairLifecycleV1::from_snapshot(snapshot).is_err());
    }

    #[test]
    fn pair_lifecycle_requires_both_receipts_before_running() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, deriver_a_verifying_key, deriver_b_verifying_key) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let receipt_a = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a.clone(),
                [0xc1; 32],
                1,
                100,
                signing_keys,
            )
            .expect("Deriver A preparation");
        assert!(lifecycle.state().is_none());
        let receipt_b = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc2; 32],
                2,
                100,
                signing_keys,
            )
            .expect("Deriver B preparation");
        lifecycle
            .begin(
                &pair,
                &receipt_a,
                &receipt_b,
                deriver_a_verifying_key,
                deriver_b_verifying_key,
                3,
            )
            .expect("both receipts should start the pair");
        assert!(matches!(
            lifecycle.state(),
            Some(LocalEd25519YaoPairLifecycleStateV1::Running { .. })
        ));
        lifecycle
            .burn(pair.pair_digest().bytes)
            .expect("running pair should burn");
        assert!(lifecycle.completed(pair.pair_digest().bytes).is_err());
    }

    #[test]
    fn pair_lifecycle_marks_expired_before_running() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, deriver_a_verifying_key, deriver_b_verifying_key) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let receipt_a = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc1; 32],
                1,
                10,
                signing_keys,
            )
            .expect("Deriver A preparation");
        let receipt_b = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc2; 32],
                2,
                10,
                signing_keys,
            )
            .expect("Deriver B preparation");

        assert!(lifecycle
            .begin(
                &pair,
                &receipt_a,
                &receipt_b,
                deriver_a_verifying_key,
                deriver_b_verifying_key,
                10,
            )
            .is_err());
        assert!(matches!(
            lifecycle.state(),
            Some(LocalEd25519YaoPairLifecycleStateV1::Expired { .. })
        ));
        assert!(lifecycle.burn(pair.pair_digest().bytes).is_err());
    }

    #[test]
    fn pair_lifecycle_reuses_exact_preparation_and_rejects_root_conflicts() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, _, _) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let first = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a.clone(),
                [0xc1; 32],
                1,
                100,
                signing_keys,
            )
            .expect("first preparation");
        let retry = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a.clone(),
                [0xc1; 32],
                50,
                150,
                signing_keys,
            )
            .expect("same preparation retry");
        assert_eq!(first, retry);
        assert!(lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc2; 32],
                2,
                100,
                signing_keys,
            )
            .is_err());
        lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc1; 32],
                2,
                100,
                signing_keys,
            )
            .expect("Deriver B preparation should retain its role-local root");
    }

    #[test]
    fn pair_lifecycle_preserves_role_receipts_when_b_prepares_first() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, deriver_a_verifying_key, deriver_b_verifying_key) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let receipt_b = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc2; 32],
                1,
                100,
                signing_keys,
            )
            .expect("Deriver B preparation");
        let receipt_a = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc1; 32],
                2,
                100,
                signing_keys,
            )
            .expect("Deriver A preparation");
        lifecycle
            .begin(
                &pair,
                &receipt_a,
                &receipt_b,
                deriver_a_verifying_key,
                deriver_b_verifying_key,
                3,
            )
            .expect("role-specific receipts should remain verifiable");
    }

    #[test]
    fn pair_lifecycle_redelivers_exact_completed_outputs() {
        let (pair, input_a, input_b) = pair_fixture();
        let (signing_keys, deriver_a_verifying_key, deriver_b_verifying_key) = signing_keys();
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let receipt_a = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                input_a,
                [0xc1; 32],
                1,
                100,
                signing_keys,
            )
            .expect("Deriver A preparation");
        let receipt_b = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                input_b,
                [0xc2; 32],
                2,
                100,
                signing_keys,
            )
            .expect("Deriver B preparation");
        lifecycle
            .begin(
                &pair,
                &receipt_a,
                &receipt_b,
                deriver_a_verifying_key,
                deriver_b_verifying_key,
                3,
            )
            .expect("both receipts should start the pair");

        let binding = pair.binding().clone();
        let transcript = [0xd1; 32];
        let execution_for = |role| {
            let client_package = Ed25519YaoEncryptedPackageV1::new(
                Ed25519YaoPackageKindV1::ActivationClient,
                role,
                pair.session(),
                transcript,
                [0xe1; 32],
                vec![0xf1; 16],
            )
            .expect("client package");
            let signing_worker_package = Ed25519YaoEncryptedPackageV1::new(
                Ed25519YaoPackageKindV1::ActivationSigningWorker,
                role,
                pair.session(),
                transcript,
                [0xe2; 32],
                vec![0xf2; 16],
            )
            .expect("Signing Worker package");
            Ed25519YaoRoleExecutionV1::Activation(
                router_ab_ed25519_yao::Ed25519YaoActivationRoleExecutionV1::new(
                    binding.clone(),
                    role,
                    transcript,
                    [0xa1; 32],
                    [0xa2; 32],
                    client_package,
                    signing_worker_package,
                )
                .expect("activation execution"),
            )
        };
        let execution_a = execution_for(Ed25519YaoDeriverRoleV1::DeriverA);
        let execution_b = execution_for(Ed25519YaoDeriverRoleV1::DeriverB);
        lifecycle
            .complete(&pair, execution_a.clone(), execution_b.clone())
            .expect("running pair should complete");
        lifecycle
            .complete(&pair, execution_a.clone(), execution_b.clone())
            .expect("exact completed retry should be idempotent");
        let (stored_a, stored_b) = lifecycle
            .completed(pair.pair_digest().bytes)
            .expect("completed pair should be readable");
        assert_eq!(stored_a, &execution_a);
        assert_eq!(stored_b, &execution_b);
    }
}
