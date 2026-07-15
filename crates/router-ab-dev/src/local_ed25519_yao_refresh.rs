use core::{cmp::Ordering, fmt};

use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoRefreshBindingV1, Ed25519YaoStableKeyContextBindingV1,
    Ed25519YaoStateEpochV1, RootShareEpoch, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use signer_core::ed25519_yao_derivation::{
    apply_ed25519_yao_refresh_delta_to_deriver_a_v1,
    apply_ed25519_yao_refresh_delta_to_deriver_b_v1, Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoJointRefreshDeltaV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoDeriverARefreshDeltaWireV1 {
    pub binding_digest: [u8; 32],
    pub session: [u8; 32],
    pub delta_y: [u8; 32],
    pub delta_tau: [u8; 32],
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoDeriverBRefreshDeltaWireV1 {
    pub binding_digest: [u8; 32],
    pub session: [u8; 32],
    pub delta_y: [u8; 32],
    pub delta_tau: [u8; 32],
}

macro_rules! impl_delta_wire {
    ($name:ident, $role:literal) => {
        impl $name {
            pub fn validate(
                &self,
                binding: &Ed25519YaoRefreshBindingV1,
                binding_digest: [u8; 32],
            ) -> RouterAbProtocolResult<()> {
                if self.binding_digest != binding_digest
                    || self.session != binding.ceremony().session_id.into_bytes()
                {
                    return Err(invalid_refresh(concat!(
                        $role,
                        " refresh delta binding does not match"
                    )));
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

impl_delta_wire!(LocalEd25519YaoDeriverARefreshDeltaWireV1, "Deriver A");
impl_delta_wire!(LocalEd25519YaoDeriverBRefreshDeltaWireV1, "Deriver B");

pub fn generate_local_ed25519_yao_deriver_a_refresh_delta_v1(
    binding: &Ed25519YaoRefreshBindingV1,
    binding_digest: [u8; 32],
) -> LocalEd25519YaoDeriverARefreshDeltaWireV1 {
    let (delta_y, delta_tau) = fresh_refresh_delta_bytes();
    LocalEd25519YaoDeriverARefreshDeltaWireV1 {
        binding_digest,
        session: binding.ceremony().session_id.into_bytes(),
        delta_y,
        delta_tau,
    }
}

pub fn generate_local_ed25519_yao_deriver_b_refresh_delta_v1(
    binding: &Ed25519YaoRefreshBindingV1,
    binding_digest: [u8; 32],
) -> LocalEd25519YaoDeriverBRefreshDeltaWireV1 {
    let (delta_y, delta_tau) = fresh_refresh_delta_bytes();
    LocalEd25519YaoDeriverBRefreshDeltaWireV1 {
        binding_digest,
        session: binding.ceremony().session_id.into_bytes(),
        delta_y,
        delta_tau,
    }
}

pub fn derive_local_ed25519_yao_joint_refresh_delta_v1(
    binding: &Ed25519YaoRefreshBindingV1,
    binding_digest: [u8; 32],
    deriver_a: &LocalEd25519YaoDeriverARefreshDeltaWireV1,
    deriver_b: &LocalEd25519YaoDeriverBRefreshDeltaWireV1,
) -> RouterAbProtocolResult<Ed25519YaoJointRefreshDeltaV1> {
    deriver_a.validate(binding, binding_digest)?;
    deriver_b.validate(binding, binding_digest)?;
    signer_core::ed25519_yao_derivation::derive_ed25519_yao_joint_refresh_delta_v1(
        signer_core::ed25519_yao_derivation::Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
            deriver_a.delta_y,
            deriver_a.delta_tau,
        )
        .map_err(map_signer_core_error)?,
        signer_core::ed25519_yao_derivation::Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
            deriver_b.delta_y,
            deriver_b.delta_tau,
        )
        .map_err(map_signer_core_error)?,
    )
    .map_err(map_signer_core_error)
}

fn fresh_refresh_delta_bytes() -> ([u8; 32], [u8; 32]) {
    let mut delta_y = [0_u8; 32];
    let mut delta_tau_wide = [0_u8; 64];
    OsRng.fill_bytes(&mut delta_y);
    OsRng.fill_bytes(&mut delta_tau_wide);
    let delta_tau = Scalar::from_bytes_mod_order_wide(&delta_tau_wide).to_bytes();
    delta_tau_wide.zeroize();
    (delta_y, delta_tau)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalEd25519YaoEffectiveIdentityV1 {
    stable_key_context_binding: Ed25519YaoStableKeyContextBindingV1,
    root_share_epoch: RootShareEpoch,
    account_id: String,
    signer_set_id: String,
    signing_worker_id: String,
}

impl LocalEd25519YaoEffectiveIdentityV1 {
    pub(crate) fn from_binding(binding: &Ed25519YaoCeremonyBindingV1) -> Self {
        Self {
            stable_key_context_binding: binding.stable_key_context_binding,
            root_share_epoch: binding.lifecycle.root_share_epoch.clone(),
            account_id: binding.lifecycle.account_id.clone(),
            signer_set_id: binding.lifecycle.signer_set_id.clone(),
            signing_worker_id: binding.lifecycle.selected_server_id.clone(),
        }
    }

    fn matches(&self, binding: &Ed25519YaoCeremonyBindingV1) -> bool {
        self.stable_key_context_binding == binding.stable_key_context_binding
            && self.root_share_epoch == binding.lifecycle.root_share_epoch
            && self.account_id == binding.lifecycle.account_id
            && self.signer_set_id == binding.lifecycle.signer_set_id
            && self.signing_worker_id == binding.lifecycle.selected_server_id
    }

    pub(crate) fn validate_persisted_v1(&self) -> RouterAbProtocolResult<()> {
        if self
            .stable_key_context_binding
            .into_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || self.account_id.trim().is_empty()
            || self.signer_set_id.trim().is_empty()
            || self.signing_worker_id.trim().is_empty()
        {
            return Err(invalid_refresh(
                "persisted Ed25519 Yao effective identity is invalid",
            ));
        }
        Ok(())
    }
}

impl Ord for LocalEd25519YaoEffectiveIdentityV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.stable_key_context_binding
            .into_bytes()
            .cmp(&other.stable_key_context_binding.into_bytes())
            .then_with(|| {
                self.root_share_epoch
                    .as_str()
                    .cmp(other.root_share_epoch.as_str())
            })
            .then_with(|| self.account_id.cmp(&other.account_id))
            .then_with(|| self.signer_set_id.cmp(&other.signer_set_id))
            .then_with(|| self.signing_worker_id.cmp(&other.signing_worker_id))
    }
}

impl PartialOrd for LocalEd25519YaoEffectiveIdentityV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

macro_rules! define_effective_state {
    ($state:ident, $prepared:ident, $server:ty, $apply:ident, $role_epoch:ident, $role:literal) => {
        #[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
        #[serde(deny_unknown_fields)]
        pub struct $state {
            y: [u8; 32],
            tau: [u8; 32],
            #[zeroize(skip)]
            epoch: Ed25519YaoStateEpochV1,
            #[zeroize(skip)]
            identity: LocalEd25519YaoEffectiveIdentityV1,
        }

        impl $state {
            pub fn from_initial(
                binding: &Ed25519YaoCeremonyBindingV1,
                epoch: Ed25519YaoStateEpochV1,
                contribution: $server,
            ) -> RouterAbProtocolResult<Self> {
                binding.validate()?;
                let (y, tau) = contribution.into_parts();
                Ok(Self {
                    y: y.into_bytes(),
                    tau: tau.into_bytes(),
                    epoch,
                    identity: LocalEd25519YaoEffectiveIdentityV1::from_binding(binding),
                })
            }

            pub const fn active_epoch(&self) -> Ed25519YaoStateEpochV1 {
                self.epoch
            }

            pub fn active_contribution(&self) -> $server {
                <$server>::from_secret_bytes(self.y, self.tau)
            }

            pub(crate) fn identity(&self) -> &LocalEd25519YaoEffectiveIdentityV1 {
                &self.identity
            }

            pub fn prepare_refresh(
                &self,
                binding: &Ed25519YaoRefreshBindingV1,
                delta: &Ed25519YaoJointRefreshDeltaV1,
            ) -> RouterAbProtocolResult<$prepared> {
                self.validate_refresh_binding(binding)?;
                let transition = binding.epochs().$role_epoch;
                let contribution =
                    $apply(self.active_contribution(), delta).map_err(map_signer_core_error)?;
                let (y, tau) = contribution.into_parts();
                Ok($prepared {
                    y: y.into_bytes(),
                    tau: tau.into_bytes(),
                    current_epoch: transition.current(),
                    next_epoch: transition.next(),
                    identity: self.identity.clone(),
                })
            }

            pub fn validate_refresh_binding(
                &self,
                binding: &Ed25519YaoRefreshBindingV1,
            ) -> RouterAbProtocolResult<()> {
                binding.ceremony().validate()?;
                let transition = binding.epochs().$role_epoch;
                if !self.identity.matches(binding.ceremony()) || transition.current() != self.epoch
                {
                    return Err(invalid_refresh(concat!(
                        $role,
                        " refresh does not match active identity and epoch"
                    )));
                }
                Ok(())
            }

            pub fn promote(&mut self, prepared: $prepared) -> RouterAbProtocolResult<()> {
                if prepared.current_epoch != self.epoch || prepared.identity != self.identity {
                    return Err(invalid_refresh(concat!(
                        $role,
                        " prepared refresh is stale"
                    )));
                }
                self.y = prepared.y;
                self.tau = prepared.tau;
                self.epoch = prepared.next_epoch;
                Ok(())
            }
        }

        impl fmt::Debug for $state {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($state))
                    .field("epoch", &self.epoch)
                    .field("contribution", &"[REDACTED]")
                    .finish()
            }
        }

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $prepared {
            y: [u8; 32],
            tau: [u8; 32],
            #[zeroize(skip)]
            current_epoch: Ed25519YaoStateEpochV1,
            #[zeroize(skip)]
            next_epoch: Ed25519YaoStateEpochV1,
            #[zeroize(skip)]
            identity: LocalEd25519YaoEffectiveIdentityV1,
        }

        impl $prepared {
            pub fn candidate_contribution(&self) -> $server {
                <$server>::from_secret_bytes(self.y, self.tau)
            }

            pub const fn current_epoch(&self) -> Ed25519YaoStateEpochV1 {
                self.current_epoch
            }

            pub const fn next_epoch(&self) -> Ed25519YaoStateEpochV1 {
                self.next_epoch
            }
        }

        impl fmt::Debug for $prepared {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($prepared))
                    .field("current_epoch", &self.current_epoch)
                    .field("next_epoch", &self.next_epoch)
                    .field("contribution", &"[REDACTED]")
                    .finish()
            }
        }
    };
}

define_effective_state!(
    LocalEd25519YaoDeriverAEffectiveStateV1,
    LocalEd25519YaoDeriverAPreparedRefreshV1,
    Ed25519YaoDeriverAServerContributionV1,
    apply_ed25519_yao_refresh_delta_to_deriver_a_v1,
    deriver_a,
    "Deriver A"
);
define_effective_state!(
    LocalEd25519YaoDeriverBEffectiveStateV1,
    LocalEd25519YaoDeriverBPreparedRefreshV1,
    Ed25519YaoDeriverBServerContributionV1,
    apply_ed25519_yao_refresh_delta_to_deriver_b_v1,
    deriver_b,
    "Deriver B"
);

fn invalid_refresh(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

fn map_signer_core_error(error: signer_core::error::SignerCoreError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        format!("local Ed25519 Yao refresh contribution failed: {error}"),
    )
}
