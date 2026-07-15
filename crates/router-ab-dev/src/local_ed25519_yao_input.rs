use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{OsRng, TryRngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoInputKindV1, Ed25519YaoOperationV1, Ed25519YaoRefreshBindingV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use router_ab_ed25519_yao::{ed25519_yao_input_aad_v1, ED25519_YAO_INPUT_HPKE_INFO_V1};

use super::{
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoRecipientPrivateKeyV1, LocalEd25519YaoRefreshDeriverARequestV1,
    LocalEd25519YaoRefreshDeriverBRequestV1,
};

type InputHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoEncryptedRefreshInputV1 {
    pub deriver: Ed25519YaoDeriverRoleV1,
    pub session: [u8; 32],
    pub stable_context_binding: [u8; 32],
    pub refresh_binding_digest: [u8; 32],
    pub encapsulated_key: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl LocalEd25519YaoEncryptedRefreshInputV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.session.iter().all(|byte| *byte == 0)
            || self.refresh_binding_digest.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_input("refresh input binding is zero"));
        }
        if self.ciphertext.len() < 16 {
            return Err(invalid_input("refresh input ciphertext is too short"));
        }
        Ok(())
    }
}

pub fn seal_local_ed25519_yao_activation_deriver_a_input_v1(
    request: &LocalEd25519YaoActivationDeriverARequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedInputV1> {
    seal_input(
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverA,
        &request.binding,
        public_key,
        request,
    )
}

pub fn seal_local_ed25519_yao_activation_deriver_b_input_v1(
    request: &LocalEd25519YaoActivationDeriverBRequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedInputV1> {
    seal_input(
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverB,
        &request.binding,
        public_key,
        request,
    )
}

pub fn seal_local_ed25519_yao_export_deriver_a_input_v1(
    request: &LocalEd25519YaoExportDeriverARequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedInputV1> {
    seal_input(
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverA,
        &request.binding,
        public_key,
        request,
    )
}

pub fn seal_local_ed25519_yao_export_deriver_b_input_v1(
    request: &LocalEd25519YaoExportDeriverBRequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedInputV1> {
    seal_input(
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverB,
        &request.binding,
        public_key,
        request,
    )
}

pub fn seal_local_ed25519_yao_refresh_deriver_a_input_v1(
    request: &LocalEd25519YaoRefreshDeriverARequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<LocalEd25519YaoEncryptedRefreshInputV1> {
    seal_refresh_input(
        Ed25519YaoDeriverRoleV1::DeriverA,
        &request.binding,
        public_key,
        request,
    )
}

pub fn seal_local_ed25519_yao_refresh_deriver_b_input_v1(
    request: &LocalEd25519YaoRefreshDeriverBRequestV1,
    public_key: [u8; 32],
) -> RouterAbProtocolResult<LocalEd25519YaoEncryptedRefreshInputV1> {
    seal_refresh_input(
        Ed25519YaoDeriverRoleV1::DeriverB,
        &request.binding,
        public_key,
        request,
    )
}

pub fn open_local_ed25519_yao_activation_deriver_a_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoActivationDeriverARequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverA,
        private_key,
    )
}

pub fn open_local_ed25519_yao_activation_deriver_b_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoActivationDeriverBRequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverB,
        private_key,
    )
}

pub fn open_local_ed25519_yao_export_deriver_a_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoExportDeriverARequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverA,
        private_key,
    )
}

pub fn open_local_ed25519_yao_export_deriver_b_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoExportDeriverBRequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverB,
        private_key,
    )
}

pub fn open_local_ed25519_yao_refresh_deriver_a_input_v1(
    envelope: &LocalEd25519YaoEncryptedRefreshInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRefreshDeriverARequestV1> {
    open_refresh_input(envelope, Ed25519YaoDeriverRoleV1::DeriverA, private_key)
}

pub fn open_local_ed25519_yao_refresh_deriver_b_input_v1(
    envelope: &LocalEd25519YaoEncryptedRefreshInputV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRefreshDeriverBRequestV1> {
    open_refresh_input(envelope, Ed25519YaoDeriverRoleV1::DeriverB, private_key)
}

fn seal_refresh_input<Request: Serialize>(
    deriver: Ed25519YaoDeriverRoleV1,
    binding: &Ed25519YaoRefreshBindingV1,
    public_key: [u8; 32],
    request: &Request,
) -> RouterAbProtocolResult<LocalEd25519YaoEncryptedRefreshInputV1> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&public_key).map_err(map_hpke_error)?;
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(request)
            .map_err(|_| invalid_input("refresh input request serialization failed"))?,
    );
    let session = binding.ceremony().session_id.into_bytes();
    let stable_context_binding = binding.ceremony().stable_key_context_binding.into_bytes();
    let refresh_binding_digest = local_ed25519_yao_refresh_binding_digest_v1(binding);
    let aad = refresh_input_aad(
        deriver,
        session,
        stable_context_binding,
        refresh_binding_digest,
    );
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (encapsulated_key, ciphertext) = InputHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_INPUT_HPKE_INFO_V1,
        &aad,
        &plaintext,
    )
    .map_err(map_hpke_error)?;
    plaintext.zeroize();
    let envelope = LocalEd25519YaoEncryptedRefreshInputV1 {
        deriver,
        session,
        stable_context_binding,
        refresh_binding_digest,
        encapsulated_key: encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| invalid_input("refresh input encapsulated key has wrong length"))?,
        ciphertext,
    };
    envelope.validate()?;
    Ok(envelope)
}

fn open_refresh_input<Request: DeserializeOwned + BoundRefreshInput>(
    envelope: &LocalEd25519YaoEncryptedRefreshInputV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Request> {
    envelope.validate()?;
    if envelope.deriver != expected_deriver {
        return Err(invalid_input("refresh input role is invalid"));
    }
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&envelope.encapsulated_key)
        .map_err(map_hpke_error)?;
    let private_key =
        DhKemX25519HkdfSha256::sk_from_bytes(private_key.as_bytes()).map_err(map_hpke_error)?;
    let aad = refresh_input_aad(
        envelope.deriver,
        envelope.session,
        envelope.stable_context_binding,
        envelope.refresh_binding_digest,
    );
    let mut plaintext = Zeroizing::new(
        InputHpkeV1::open_base(
            &encapsulated_key,
            &private_key,
            ED25519_YAO_INPUT_HPKE_INFO_V1,
            &aad,
            &envelope.ciphertext,
        )
        .map_err(map_hpke_error)?,
    );
    let request = serde_json::from_slice::<Request>(&plaintext)
        .map_err(|_| invalid_input("refresh input plaintext is malformed"))?;
    plaintext.zeroize();
    let binding = request.refresh_binding();
    if binding.ceremony().session_id.into_bytes() != envelope.session
        || binding.ceremony().stable_key_context_binding.into_bytes()
            != envelope.stable_context_binding
        || local_ed25519_yao_refresh_binding_digest_v1(binding) != envelope.refresh_binding_digest
    {
        return Err(invalid_input(
            "refresh input envelope does not match its admitted binding",
        ));
    }
    Ok(request)
}

fn seal_input<Request: Serialize>(
    kind: Ed25519YaoInputKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    binding: &Ed25519YaoCeremonyBindingV1,
    public_key: [u8; 32],
    request: &Request,
) -> RouterAbProtocolResult<Ed25519YaoEncryptedInputV1> {
    if !operation_matches_kind(binding.operation, kind) {
        return Err(invalid_input(
            "Deriver input request selected the wrong circuit family",
        ));
    }
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&public_key).map_err(map_hpke_error)?;
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(request)
            .map_err(|_| invalid_input("Deriver input request serialization failed"))?,
    );
    let session = binding.session_id.into_bytes();
    let stable_context_binding = binding.stable_key_context_binding.into_bytes();
    let aad = ed25519_yao_input_aad_v1(
        kind,
        deriver,
        binding.operation,
        session,
        stable_context_binding,
    );
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (encapsulated_key, ciphertext) = InputHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_INPUT_HPKE_INFO_V1,
        &aad,
        &plaintext,
    )
    .map_err(map_hpke_error)?;
    plaintext.zeroize();
    Ed25519YaoEncryptedInputV1::new(
        kind,
        deriver,
        binding.operation,
        session,
        stable_context_binding,
        encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| invalid_input("Deriver input encapsulated key has wrong length"))?,
        ciphertext,
    )
}

fn open_input<Request: DeserializeOwned + BoundInput>(
    envelope: &Ed25519YaoEncryptedInputV1,
    expected_kind: Ed25519YaoInputKindV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Request> {
    envelope.validate()?;
    if envelope.kind() != expected_kind || envelope.deriver() != expected_deriver {
        return Err(invalid_input(
            "Deriver input role or circuit family is invalid",
        ));
    }
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(envelope.encapsulated_key())
        .map_err(map_hpke_error)?;
    let private_key =
        DhKemX25519HkdfSha256::sk_from_bytes(private_key.as_bytes()).map_err(map_hpke_error)?;
    let aad = ed25519_yao_input_aad_v1(
        envelope.kind(),
        envelope.deriver(),
        envelope.operation(),
        envelope.session(),
        envelope.stable_context_binding(),
    );
    let mut plaintext = Zeroizing::new(
        InputHpkeV1::open_base(
            &encapsulated_key,
            &private_key,
            ED25519_YAO_INPUT_HPKE_INFO_V1,
            &aad,
            envelope.ciphertext(),
        )
        .map_err(map_hpke_error)?,
    );
    let request = serde_json::from_slice::<Request>(&plaintext)
        .map_err(|_| invalid_input("Deriver input plaintext is malformed"))?;
    plaintext.zeroize();
    let binding = request.binding();
    if binding.operation != envelope.operation()
        || binding.session_id.into_bytes() != envelope.session()
        || binding.stable_key_context_binding.into_bytes() != envelope.stable_context_binding()
    {
        return Err(invalid_input(
            "Deriver input envelope does not match its admitted binding",
        ));
    }
    Ok(request)
}

trait BoundInput {
    fn binding(&self) -> &Ed25519YaoCeremonyBindingV1;
}

trait BoundRefreshInput {
    fn refresh_binding(&self) -> &Ed25519YaoRefreshBindingV1;
}

macro_rules! impl_bound_input {
    ($($request:ty),+ $(,)?) => {
        $(
            impl BoundInput for $request {
                fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
                    &self.binding
                }
            }
        )+
    };
}

impl_bound_input!(
    LocalEd25519YaoActivationDeriverARequestV1,
    LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoExportDeriverARequestV1,
    LocalEd25519YaoExportDeriverBRequestV1,
);

impl BoundRefreshInput for LocalEd25519YaoRefreshDeriverARequestV1 {
    fn refresh_binding(&self) -> &Ed25519YaoRefreshBindingV1 {
        &self.binding
    }
}

impl BoundRefreshInput for LocalEd25519YaoRefreshDeriverBRequestV1 {
    fn refresh_binding(&self) -> &Ed25519YaoRefreshBindingV1 {
        &self.binding
    }
}

fn operation_matches_kind(operation: Ed25519YaoOperationV1, kind: Ed25519YaoInputKindV1) -> bool {
    matches!(
        (operation, kind),
        (
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery,
            Ed25519YaoInputKindV1::Activation
        ) | (Ed25519YaoOperationV1::Export, Ed25519YaoInputKindV1::Export)
    )
}

fn refresh_input_aad(
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    stable_context_binding: [u8; 32],
    refresh_binding_digest: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(132);
    aad.extend_from_slice(b"seams/router-ab/ed25519-yao/deriver-refresh-input/aad/v1");
    aad.push(deriver.wire_tag());
    aad.extend_from_slice(&session);
    aad.extend_from_slice(&stable_context_binding);
    aad.extend_from_slice(&refresh_binding_digest);
    aad
}

pub fn local_ed25519_yao_refresh_binding_digest_v1(
    binding: &Ed25519YaoRefreshBindingV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/refresh-binding/v1");
    hasher.update(binding.ceremony().session_id.into_bytes());
    hasher.update(binding.ceremony().stable_key_context_binding.into_bytes());
    hasher.update(binding.registered_public_key());
    for transition in [
        binding.epochs().deriver_a,
        binding.epochs().deriver_b,
        binding.epochs().signing_worker,
    ] {
        hasher.update(transition.current().get().to_be_bytes());
        hasher.update(transition.next().get().to_be_bytes());
    }
    hasher.finalize().into()
}

fn map_hpke_error(_: hpke_ng::HpkeError) -> RouterAbProtocolError {
    invalid_input("Deriver input HPKE operation failed")
}

fn invalid_input(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLocalHttpRequest, message)
}
