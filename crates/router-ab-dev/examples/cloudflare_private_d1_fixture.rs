use base64::Engine;
use router_ab_cloudflare::{
    CloudflareEd25519YaoPairPrepareRequestV1, CloudflareEd25519YaoPairWorkV1,
};
use router_ab_core::{
    ed25519_yao_recipient_set_digest_v1, LocalServiceRoleV1, MpcMaterialActivationRefV1,
    RootShareEpoch, RouterEd25519YaoGatewayExecuteTargetV2, TenantRootCreationGrantNonceV1,
    TenantRootCreationGrantV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
};
use router_ab_dev::{
    admit_local_ed25519_yao_registration_v1, derive_local_ed25519_yao_recipient_key_pair_v1,
    local_env_materialization_plan_v1, parse_local_env_file_contents_v1,
    seal_local_ed25519_yao_activation_deriver_a_input_v1,
    seal_local_ed25519_yao_activation_deriver_b_input_v1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoLifecycleScopeV1,
    RouterAbEd25519YaoRegistrationAdmissionRequestV1,
};
use serde::Serialize;
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientRootV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

const INTERNAL_AUTH_SECRET: &str = "private-d1-integration-auth";
const TENANT_ROOT_ISSUER_KEY_ID: &str = "miniflare-tenant-root-control-plane-issuer-v1";
const TENANT_ROOT_ISSUER_SEED: [u8; 32] = [0xc1; 32];
const TENANT_ROOT_GRANT_KEY_ID: &str = "miniflare-tenant-root-grant-authority-v1";
const TENANT_ROOT_GRANT_SEED: [u8; 32] = [0xc2; 32];
const TENANT_ROOT_ROLE_A_KEY_ID: &str = "miniflare-tenant-root-role-a-v1";
const TENANT_ROOT_ROLE_B_KEY_ID: &str = "miniflare-tenant-root-role-b-v1";
const TENANT_ROOT_ROLE_A_SEED: [u8; 32] = [0xa4; 32];
const TENANT_ROOT_ROLE_B_SEED: [u8; 32] = [0xb4; 32];

#[derive(Serialize)]
struct RequestFixture {
    gateway_request: RouterEd25519YaoGatewayExecuteTargetV2,
    prepare_a: CloudflareEd25519YaoPairPrepareRequestV1,
    prepare_b: CloudflareEd25519YaoPairPrepareRequestV1,
    conflicting_prepare_a: CloudflareEd25519YaoPairPrepareRequestV1,
}

#[derive(Serialize)]
struct PrivateD1Fixture {
    router_env: BTreeMap<String, String>,
    deriver_a_env: BTreeMap<String, String>,
    deriver_b_env: BTreeMap<String, String>,
    signing_worker_env: BTreeMap<String, String>,
    tenant_root_control_plane_env: BTreeMap<String, String>,
    tenant_root_creation: TenantRootCreationFixture,
    role_retry: RequestFixture,
    activation: RequestFixture,
}

#[derive(Serialize)]
struct TenantRootCreationFixture {
    interrupted: TenantRootCreationRequestFixture,
    fresh: TenantRootCreationRequestFixture,
}

#[derive(Serialize)]
struct TenantRootCreationRequestFixture {
    creation_grant_b64u: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plan = local_env_materialization_plan_v1(b"cloudflare-private-d1-integration-v1")?;
    let local_envs = local_env_maps(&plan)?;
    let router_local = role_env(&local_envs, LocalServiceRoleV1::Router)?;
    let deriver_a_local = role_env(&local_envs, LocalServiceRoleV1::DeriverA)?;
    let deriver_b_local = role_env(&local_envs, LocalServiceRoleV1::DeriverB)?;
    let signing_worker_local = role_env(&local_envs, LocalServiceRoleV1::SigningWorker)?;

    let deriver_a_public =
        x25519_public_key(router_local, "DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY")?;
    let deriver_b_public =
        x25519_public_key(router_local, "DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY")?;
    let signing_worker_public =
        x25519_public_key(router_local, "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY")?;

    let fixture = PrivateD1Fixture {
        router_env: cloudflare_router_env(router_local, deriver_a_local)?,
        deriver_a_env: cloudflare_deriver_a_env(deriver_a_local, router_local)?,
        deriver_b_env: cloudflare_deriver_b_env(deriver_b_local, router_local)?,
        signing_worker_env: cloudflare_signing_worker_env(signing_worker_local)?,
        tenant_root_control_plane_env: cloudflare_tenant_root_control_plane_env(deriver_a_local)?,
        tenant_root_creation: tenant_root_creation_fixture()?,
        role_retry: request_fixture(
            "role-private-d1-retry",
            [0x31; 32],
            deriver_a_public,
            deriver_b_public,
            signing_worker_public,
        )?,
        activation: request_fixture(
            "signing-worker-d1-activation",
            [0x32; 32],
            deriver_a_public,
            deriver_b_public,
            signing_worker_public,
        )?,
    };
    println!("{}", serde_json::to_string(&fixture)?);
    Ok(())
}

fn tenant_root_creation_fixture() -> Result<TenantRootCreationFixture, Box<dyn std::error::Error>> {
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let identity =
        TenantRootIdentityV1::new("org-miniflare", "project-r120", "test", "root-main", "v1")?;
    Ok(TenantRootCreationFixture {
        interrupted: tenant_root_creation_request(&identity, [0x22; 16], [0x33; 32], now_ms)?,
        fresh: tenant_root_creation_request(&identity, [0x23; 16], [0x34; 32], now_ms)?,
    })
}

fn tenant_root_creation_request(
    identity: &TenantRootIdentityV1,
    lineage: [u8; 16],
    nonce: [u8; 32],
    now_ms: u64,
) -> Result<TenantRootCreationRequestFixture, Box<dyn std::error::Error>> {
    let grant = TenantRootCreationGrantV1::sign(
        identity,
        TenantRootCustodyLineageId::from_bytes(lineage)?,
        TenantRootCreationGrantNonceV1::from_bytes(nonce)?,
        now_ms,
        now_ms + 60_000,
        TENANT_ROOT_GRANT_KEY_ID,
        &TENANT_ROOT_GRANT_SEED,
    )?;
    Ok(TenantRootCreationRequestFixture {
        creation_grant_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(grant.canonical_bytes()?),
    })
}

fn local_env_maps(
    plan: &router_ab_dev::LocalEnvMaterializationPlanV1,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, Box<dyn std::error::Error>> {
    let mut maps = BTreeMap::new();
    for file in &plan.files {
        maps.insert(
            file.role.as_str().to_owned(),
            parse_local_env_file_contents_v1(&file.contents)?
                .into_iter()
                .collect(),
        );
    }
    Ok(maps)
}

fn role_env<'a>(
    maps: &'a BTreeMap<String, BTreeMap<String, String>>,
    role: LocalServiceRoleV1,
) -> Result<&'a BTreeMap<String, String>, Box<dyn std::error::Error>> {
    maps.get(role.as_str())
        .ok_or_else(|| format!("missing generated env for {}", role.as_str()).into())
}

fn request_fixture(
    label: &str,
    client_root_bytes: [u8; 32],
    deriver_a_public: [u8; 32],
    deriver_b_public: [u8; 32],
    signing_worker_public: [u8; 32],
) -> Result<RequestFixture, Box<dyn std::error::Error>> {
    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(&format!("wallet-{label}"))?,
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(&format!("ed25519ks_{label}"))?,
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:local")?,
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1)?,
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)?;
    let client_root = Ed25519YaoClientRootV1::from_secret_bytes(client_root_bytes);
    let (client_a, client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let application_binding = RouterAbEd25519YaoApplicationBindingFactsV1::new(
        format!("wallet-{label}"),
        format!("ed25519ks_{label}"),
        "project:local",
        1,
    )?;
    let admission = admit_local_ed25519_yao_registration_v1(
        RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(
            RouterAbEd25519YaoLifecycleScopeV1::new(
                format!("{label}-session"),
                RootShareEpoch::new("local-root-v1")?,
                format!("{label}-account"),
                format!("{label}-wallet-session"),
                format!("{label}-signer-set"),
                "signing-worker-local",
                MpcMaterialActivationRefV1::new(
                    format!("activation-{label}"),
                    format!("capability-{label}"),
                    format!("{label}-account"),
                    format!("key-{label}"),
                    format!("{label}-session"),
                    "signing-worker-local",
                )?,
            )?,
            application_binding.clone(),
            [1, 2],
        )?,
    )?;
    let client_recipient = derive_local_ed25519_yao_recipient_key_pair_v1(
        &[client_root_bytes[0].wrapping_add(0x40); 32],
    )?;
    let recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: client_recipient.public_key,
        signing_worker_public_key: signing_worker_public,
    };
    let (client_a_y, client_a_tau) = client_a.into_parts();
    let (client_b_y, client_b_tau) = client_b.into_parts();
    let request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding: admission.binding.clone(),
        application_binding: application_binding.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_a_y.into_bytes(),
            tau: client_a_tau.into_bytes(),
        },
        recipients,
    };
    let request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: admission.binding.clone(),
        application_binding,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_b_y.into_bytes(),
            tau: client_b_tau.into_bytes(),
        },
        recipients,
    };
    let input_a =
        seal_local_ed25519_yao_activation_deriver_a_input_v1(&request_a, deriver_a_public)?;
    let input_b =
        seal_local_ed25519_yao_activation_deriver_b_input_v1(&request_b, deriver_b_public)?;
    let conflicting_input_a =
        seal_local_ed25519_yao_activation_deriver_a_input_v1(&request_a, deriver_a_public)?;
    let gateway_request = RouterEd25519YaoGatewayExecuteTargetV2::registration(
        admission.binding.clone(),
        input_a,
        input_b,
    )?;
    let conflicting_gateway_request = RouterEd25519YaoGatewayExecuteTargetV2::registration(
        admission.binding,
        conflicting_input_a.clone(),
        gateway_request.inputs().1.clone(),
    )?;
    let recipient_set_digest = ed25519_yao_recipient_set_digest_v1(
        deriver_a_public,
        deriver_b_public,
        signing_worker_public,
    )?;
    let execute =
        gateway_request
            .clone()
            .into_execute_request(recipient_set_digest, 1, u64::MAX)?;
    let conflicting_execute =
        conflicting_gateway_request.into_execute_request(recipient_set_digest, 1, u64::MAX)?;
    let (input_a, input_b) = gateway_request.inputs();
    let input_a = input_a.clone();
    let input_b = input_b.clone();
    Ok(RequestFixture {
        gateway_request,
        prepare_a: CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: execute.pair_binding().clone(),
            work: CloudflareEd25519YaoPairWorkV1::Ceremony,
            input: input_a,
        },
        prepare_b: CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: execute.pair_binding().clone(),
            work: CloudflareEd25519YaoPairWorkV1::Ceremony,
            input: input_b,
        },
        conflicting_prepare_a: CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: conflicting_execute.pair_binding().clone(),
            work: CloudflareEd25519YaoPairWorkV1::Ceremony,
            input: conflicting_input_a,
        },
    })
}

fn cloudflare_router_env(
    local: &BTreeMap<String, String>,
    deriver_local: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let mut env = BTreeMap::from([
        ("ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING".into(), "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into()),
        ("ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(), INTERNAL_AUTH_SECRET.into()),
        ("ROUTER_JWT_ISSUER".into(), "https://issuer.example".into()),
        ("ROUTER_JWT_AUDIENCE".into(), "router-ab".into()),
        ("ROUTER_JWT_JWKS_JSON".into(), "{\"keys\":[{\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"test\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}".into()),
        ("DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH".into(), "epoch-1".into()),
        ("DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY".into(), required(local, "DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY")),
        ("DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH".into(), "epoch-1".into()),
        ("DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY".into(), required(local, "DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY")),
        ("DERIVER_A_PEER_VERIFYING_KEY_HEX".into(), required(deriver_local, "DERIVER_A_PEER_VERIFYING_KEY")),
        ("DERIVER_B_PEER_VERIFYING_KEY_HEX".into(), required(deriver_local, "DERIVER_B_PEER_VERIFYING_KEY")),
        ("SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH".into(), "epoch-1".into()),
        ("SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY".into(), required(local, "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY")),
        ("DERIVER_A_PEER_BINDING".into(), "DERIVER_A".into()),
        ("DERIVER_B_PEER_BINDING".into(), "DERIVER_B".into()),
        ("SIGNING_WORKER_PEER_BINDING".into(), "SIGNING_WORKER".into()),
    ]);
    env.insert(
        "TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON".into(),
        cloudflare_tenant_root_control_plane_issuer_verifying_keys_json()?,
    );
    env.insert(
        "ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON".into(),
        cloudflare_tenant_root_role_verifying_keys_json(),
    );
    Ok(env)
}

fn cloudflare_deriver_a_env(
    local: &BTreeMap<String, String>,
    router_local: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    cloudflare_deriver_env(local, router_local, "A", "deriver_a", "DERIVER_B")
}

fn cloudflare_deriver_b_env(
    local: &BTreeMap<String, String>,
    router_local: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    cloudflare_deriver_env(local, router_local, "B", "deriver_b", "DERIVER_A")
}

fn cloudflare_deriver_env(
    local: &BTreeMap<String, String>,
    router_local: &BTreeMap<String, String>,
    suffix: &str,
    role: &str,
    peer_binding: &str,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let lower = suffix.to_ascii_lowercase();
    let kek_seed = if lower == "a" { [0xa1; 32] } else { [0xb1; 32] };
    let kek = derive_local_ed25519_yao_recipient_key_pair_v1(&kek_seed)?;
    let private_key = required(
        local,
        &format!("DERIVER_{suffix}_ENVELOPE_HPKE_PRIVATE_KEY"),
    );
    let mut env = BTreeMap::from([
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING".into(),
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
        ),
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
            INTERNAL_AUTH_SECRET.into(),
        ),
        (
            "DERIVER_ROLE_PRIVATE_D1_KEK_BINDING".into(),
            format!("DERIVER_{suffix}_ROLE_PRIVATE_D1_KEK"),
        ),
        (
            "DERIVER_ROLE_PRIVATE_D1_KEK_VERSION".into(),
            "test-v1".into(),
        ),
        (
            "DERIVER_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY".into(),
            format!("x25519:{}", hex::encode(kek.public_key)),
        ),
        (
            "DERIVER_ROLE_PRIVATE_D1_ENVIRONMENT".into(),
            "miniflare-test".into(),
        ),
        ("DERIVER_ROLE_PRIVATE_D1_ROLE".into(), role.into()),
        (
            format!("DERIVER_{suffix}_ROLE_PRIVATE_D1_KEK"),
            format!(
                "hpke-x25519-role-private-d1-private-v1:{}",
                hex::encode(kek.private_key.as_bytes())
            ),
        ),
        (
            format!("DERIVER_{suffix}_ENVELOPE_HPKE_PRIVATE_KEY_BINDING"),
            format!("DERIVER_{suffix}_ENVELOPE_HPKE_PRIVATE_KEY"),
        ),
        (
            format!("DERIVER_{suffix}_ENVELOPE_HPKE_PRIVATE_KEY"),
            format!("hpke-x25519-private-v1:{private_key}"),
        ),
        (
            format!("DERIVER_{suffix}_ENVELOPE_HPKE_KEY_EPOCH"),
            "epoch-1".into(),
        ),
        (
            format!("DERIVER_{suffix}_ENVELOPE_HPKE_PUBLIC_KEY"),
            required(
                router_local,
                &format!("DERIVER_{suffix}_ED25519_YAO_INPUT_PUBLIC_KEY"),
            ),
        ),
        (
            format!("DERIVER_{suffix}_PEER_SIGNING_KEY_BINDING"),
            format!("DERIVER_{suffix}_PEER_SIGNING_KEY"),
        ),
        (
            format!("DERIVER_{suffix}_PEER_SIGNING_KEY"),
            required(local, &format!("DERIVER_{suffix}_PEER_SIGNING_KEY")),
        ),
        (
            format!("DERIVER_{suffix}_PEER_SIGNING_KEY_EPOCH"),
            "epoch-1".into(),
        ),
        (
            "DERIVER_A_PEER_VERIFYING_KEY_HEX".into(),
            required(local, "DERIVER_A_PEER_VERIFYING_KEY"),
        ),
        (
            "DERIVER_B_PEER_VERIFYING_KEY_HEX".into(),
            required(local, "DERIVER_B_PEER_VERIFYING_KEY"),
        ),
    ]);
    env.insert(format!("{peer_binding}_PEER_BINDING"), peer_binding.into());
    insert_cloudflare_deriver_tenant_root_env(&mut env, suffix)?;
    Ok(env)
}

/// Adds the tenant-root env surface a Deriver Worker needs to boot and to run
/// the role-private creation probe.
///
/// The published issuer keyset here is a deployment descriptor, not the probe's
/// signing authority: the creation probe carries its own issuer identity so it
/// can never be satisfied by whatever key a real deployment publishes.
fn insert_cloudflare_deriver_tenant_root_env(
    env: &mut BTreeMap<String, String>,
    suffix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let lower = suffix.to_ascii_lowercase();
    let (online_seed, backup_seed) = if lower == "a" {
        ([0xa2; 32], [0xa3; 32])
    } else {
        ([0xb2; 32], [0xb3; 32])
    };
    let online = derive_local_ed25519_yao_recipient_key_pair_v1(&online_seed)?;
    let backup = derive_local_ed25519_yao_recipient_key_pair_v1(&backup_seed)?;
    let online_binding = format!("DERIVER_{suffix}_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY");
    let backup_binding = format!("DERIVER_{suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY");

    env.insert(
        "TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON".into(),
        cloudflare_tenant_root_control_plane_issuer_verifying_keys_json()?,
    );
    env.insert(
        "ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON".into(),
        cloudflare_tenant_root_role_verifying_keys_json(),
    );
    let (role_key_id, role_seed) = if lower == "a" {
        (TENANT_ROOT_ROLE_A_KEY_ID, TENANT_ROOT_ROLE_A_SEED)
    } else {
        (TENANT_ROOT_ROLE_B_KEY_ID, TENANT_ROOT_ROLE_B_SEED)
    };
    let role_binding = format!("DERIVER_{suffix}_TENANT_ROOT_CREATION_SIGNING_KEY");
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING"),
        role_binding.clone(),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_CREATION_SIGNING_KEY_ID"),
        role_key_id.into(),
    );
    env.insert(
        role_binding,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(role_seed),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF"),
        format!("miniflare-tenant-root-{lower}-online-epoch-1"),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY"),
        format!("x25519:{}", hex::encode(online.public_key)),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING"),
        online_binding.clone(),
    );
    env.insert(
        online_binding,
        format!(
            "hpke-x25519-private-v1:{}",
            hex::encode(online.private_key.as_bytes())
        ),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID"),
        format!("miniflare-tenant-root-{lower}-managed-backup"),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION"),
        format!("miniflare-tenant-root-{lower}-backup-v1"),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY"),
        format!("x25519:{}", hex::encode(backup.public_key)),
    );
    env.insert(
        format!("DERIVER_{suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING"),
        backup_binding.clone(),
    );
    env.insert(
        backup_binding,
        format!(
            "hpke-x25519-private-v1:{}",
            hex::encode(backup.private_key.as_bytes())
        ),
    );
    Ok(())
}

/// Builds the published control-plane issuer keyset descriptor.
fn cloudflare_tenant_root_control_plane_issuer_verifying_keys_json(
) -> Result<String, Box<dyn std::error::Error>> {
    let verifying_key =
        ed25519_dalek::SigningKey::from_bytes(&TENANT_ROOT_ISSUER_SEED).verifying_key();
    Ok(format!(
        "{{\"keys\":[{{\"issuer_key_id\":\"{TENANT_ROOT_ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
        hex::encode(verifying_key.as_bytes())
    ))
}

fn cloudflare_tenant_root_role_verifying_keys_json() -> String {
    let a = ed25519_dalek::SigningKey::from_bytes(&TENANT_ROOT_ROLE_A_SEED).verifying_key();
    let b = ed25519_dalek::SigningKey::from_bytes(&TENANT_ROOT_ROLE_B_SEED).verifying_key();
    format!(
        "{{\"keys\":[{{\"role\":\"deriver_a\",\"signing_key_id\":\"{TENANT_ROOT_ROLE_A_KEY_ID}\",\"verifying_key_hex\":\"{}\"}},{{\"role\":\"deriver_b\",\"signing_key_id\":\"{TENANT_ROOT_ROLE_B_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
        hex::encode(a.as_bytes()),
        hex::encode(b.as_bytes()),
    )
}

fn cloudflare_tenant_root_control_plane_env(
    deriver_local: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let grant_key = ed25519_dalek::SigningKey::from_bytes(&TENANT_ROOT_GRANT_SEED).verifying_key();
    Ok(BTreeMap::from([
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING".into(),
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
        ),
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
            INTERNAL_AUTH_SECRET.into(),
        ),
        (
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING".into(),
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY".into(),
        ),
        (
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID".into(),
            TENANT_ROOT_ISSUER_KEY_ID.into(),
        ),
        (
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY".into(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TENANT_ROOT_ISSUER_SEED),
        ),
        (
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON".into(),
            cloudflare_tenant_root_control_plane_issuer_verifying_keys_json()?,
        ),
        (
            "TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON".into(),
            format!(
                "{{\"keys\":[{{\"issuer_key_id\":\"{TENANT_ROOT_GRANT_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
                hex::encode(grant_key.as_bytes()),
            ),
        ),
        (
            "ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON".into(),
            cloudflare_tenant_root_role_verifying_keys_json(),
        ),
        (
            "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID".into(),
            TENANT_ROOT_ROLE_A_KEY_ID.into(),
        ),
        (
            "DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID".into(),
            TENANT_ROOT_ROLE_B_KEY_ID.into(),
        ),
        (
            "DERIVER_A_PEER_VERIFYING_KEY_HEX".into(),
            required(deriver_local, "DERIVER_A_PEER_VERIFYING_KEY"),
        ),
        (
            "DERIVER_B_PEER_VERIFYING_KEY_HEX".into(),
            required(deriver_local, "DERIVER_B_PEER_VERIFYING_KEY"),
        ),
    ]))
}

fn cloudflare_signing_worker_env(
    local: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let kek = derive_local_ed25519_yao_recipient_key_pair_v1(&[0xc1; 32])?;
    let private_key = required(local, "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY");
    Ok(BTreeMap::from([
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING".into(),
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
        ),
        (
            "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET".into(),
            INTERNAL_AUTH_SECRET.into(),
        ),
        (
            "SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING".into(),
            "SIGNING_WORKER_PRESIGN_SESSION_DO".into(),
        ),
        (
            "SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT".into(),
            "private-d1-test".into(),
        ),
        (
            "SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX".into(),
            "private-d1-test/".into(),
        ),
        (
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING".into(),
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY".into(),
        ),
        (
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY".into(),
            format!("hpke-x25519-server-output-private-v1:{private_key}"),
        ),
        (
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH".into(),
            "epoch-1".into(),
        ),
        (
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY".into(),
            required(local, "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY"),
        ),
        (
            "SIGNING_WORKER_PRIVATE_D1_KEK".into(),
            format!(
                "hpke-x25519-server-output-private-v1:{}",
                hex::encode(kek.private_key.as_bytes())
            ),
        ),
        (
            "SIGNING_WORKER_PRIVATE_D1_KEK_VERSION".into(),
            "test-v1".into(),
        ),
        (
            "SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY".into(),
            format!("x25519:{}", hex::encode(kek.public_key)),
        ),
        (
            "SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT".into(),
            "miniflare-test".into(),
        ),
    ]))
}

fn required(env: &BTreeMap<String, String>, key: &str) -> String {
    env.get(key)
        .unwrap_or_else(|| panic!("generated env is missing {key}"))
        .clone()
}

fn x25519_public_key(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let encoded = required(env, key);
    let bytes = hex::decode(
        encoded
            .strip_prefix("x25519:")
            .ok_or("missing x25519 prefix")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| "invalid x25519 key length".into())
}
