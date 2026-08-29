import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildEcdsaRoleLocalPersistedMaterialRefFixture,
  buildMpcMaterialActivationRefFixture,
} from './ecdsaMaterialRef.fixtures';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionMintId,
  parseEcdsaAuthorizationSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
} from '@shared/utils/domainIds';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '@shared/device-linking/parsers';

function requireBootstrapAuthorizationId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('ecdsa bootstrap fixture authorization id is invalid');
  return result.value;
}
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/ecdsaRoleLocalRecords';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { parseRootShareEpoch, type RootShareEpoch } from '@shared/utils/domainIds';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { testEcdsaChainTarget } from './ecdsaChainTarget.fixtures';

const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SHARE32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const FIXTURE_ROLE_LOCAL_STATE_BLOB = {
  kind: 'ecdsa_role_local_state_blob_v1',
  curve: 'secp256k1',
  encoding: 'base64url',
  producer: 'signer_core',
  stateBlobB64u: VALID_ECDSA_SHARE32_B64U,
} as const;

function hexAddressToBase64Url(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

/** Brands a fixture session id as the activation epoch via the production parser. */
function fixtureRootShareEpoch(value: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) {
    throw new Error(`invalid fixture activation epoch: ${value}`);
  }
  return parsed.value;
}

function fixtureRouterAbEcdsaDerivationNormalSigning(args: {
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  sessionId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: args.signingRootId,
      signing_root_version: args.signingRootVersion,
      context: {
        application_binding_digest_b64u: VALID_ECDSA_SHARE32_B64U,
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_SHARE32_B64U,
        derivation_client_share_public_key33_b64u: args.clientVerifyingShareB64u,
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        ethereum_address20_b64u: hexAddressToBase64Url(args.ethereumAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(
        buildMpcMaterialActivationRefFixture(
          `router-ab-ecdsa:${args.walletId}:${args.ecdsaThresholdKeyId}:${args.sessionId}`,
          args.walletId,
        ),
      ),
      signing_worker: {
        server_id: 'signing-worker-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: fixtureRootShareEpoch(args.sessionId),
    },
  };
}

export function fixtureRouterAbEcdsaDerivationPublicCapability(args: {
  walletId: string;
  sessionId: string;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: args.normalSigning.scope.context,
    public_identity: args.normalSigning.scope.public_identity,
    material_activation: args.normalSigning.scope.material_activation,
    signer_set: {
      signer_set_id: 'signer-set-warm-session-fixture',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
      },
      selected_server: args.normalSigning.scope.signing_worker,
    },
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-warm-session-fixture',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-warm-session-fixture',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
    router_id: 'router-warm-session-fixture',
    client_id: args.walletId,
    activation_epoch: args.sessionId,
    registration_request_digest_b64u: VALID_ECDSA_SHARE32_B64U,
    proof_transcript_digest_b64u: VALID_ECDSA_SHARE32_B64U,
  });
}

/**
 * Default `publicCapability` for `buildEcdsaRoleLocalPublicFacts`, which has required
 * it since role-local registration and signing flows were unified. Nothing cross-checks
 * the capability against the surrounding facts, but callers pass their own identity so
 * a fixture record stays internally consistent when it is read back.
 */
export function fixtureEcdsaRoleLocalPublicCapability(args: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  sessionId?: string;
  clientVerifyingShareB64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  const sessionId = String(args.sessionId || 'activation-role-local-fixture').trim();
  return fixtureRouterAbEcdsaDerivationPublicCapability({
    walletId: args.walletId,
    sessionId,
    normalSigning: fixtureRouterAbEcdsaDerivationNormalSigning({
      walletId: args.walletId,
      walletKeyId: args.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      sessionId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress: args.ethereumAddress || `0x${'11'.repeat(20)}`,
    }),
  });
}

export function fixtureRuntimePolicyScopeFromSigningRoot(
  signingRootId: string,
  signingRootVersion: string,
): ThresholdRuntimePolicyScope | undefined {
  const delimiter = signingRootId.lastIndexOf(':');
  if (delimiter <= 0 || delimiter >= signingRootId.length - 1) return undefined;
  return {
    orgId: 'org-test',
    projectId: signingRootId.slice(0, delimiter),
    envId: signingRootId.slice(delimiter + 1),
    signingRootVersion,
  };
}

export function createThresholdEcdsaBootstrapFixture(args: {
  nearAccountId: string;
  chain: ThresholdEcdsaActivationChain;
  rpId?: string;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  walletSessionToken?: string;
  relayerUrl?: string;
  relayerKeyId?: string;
  clientVerifyingShareB64u?: string;
  passkeyCredentialIdB64u?: string;
  participantIds?: number[];
  ethereumAddress?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  roleLocalAuthMethod?: 'passkey' | 'email_otp';
  emailOtpAuthSubjectId?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const chainLabel = args.chain;
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(
    String(args.ecdsaThresholdKeyId || 'ek-shared-1').trim(),
  );
  const keyHandle = String(args.keyHandle || `ederivation-key-${ecdsaThresholdKeyId}`).trim();
  const sessionId = String(args.sessionId || `sess-${chainLabel}-1`).trim();
  const walletSessionId = requireBootstrapAuthorizationId(
    parseWalletSessionId(`ecdsa-bootstrap-wallet-session:${sessionId}`),
  );
  const authorizationId = requireBootstrapAuthorizationId(
    parseWalletSessionAuthorizationId(`ecdsa-bootstrap-authorization:${sessionId}`),
  );
  const quotaId = requireBootstrapAuthorizationId(
    parseMpcWalletSigningQuotaId(`ecdsa-bootstrap-quota:${sessionId}`),
  );
  const relayerUrl = String(args.relayerUrl || 'https://relay.example').trim();
  const rpId = String(args.rpId || 'localhost').trim();
  const relayerKeyId = String(args.relayerKeyId || `rk-${chainLabel}-1`).trim();
  const clientVerifyingShareB64u = String(
    args.clientVerifyingShareB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
  ).trim();
  const passkeyCredentialIdB64u = String(
    args.passkeyCredentialIdB64u || `passkey-credential-${ecdsaThresholdKeyId}`,
  ).trim();
  const participantIds = args.participantIds || [1, 2];
  const ethereumAddress = args.ethereumAddress || `0x${'11'.repeat(20)}`;
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || 'default').trim();
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: args.nearAccountId,
    signingRootId,
    signingRootVersion,
  });
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    fixtureRuntimePolicyScopeFromSigningRoot(signingRootId, signingRootVersion);
  if (!runtimePolicyScope) {
    throw new Error('ECDSA bootstrap fixture requires a runtime policy scope');
  }
  const chainTarget = testEcdsaChainTarget(args.chain);
  const roleLocalAuthMethod =
    args.roleLocalAuthMethod === 'email_otp'
      ? buildEcdsaRoleLocalEmailOtpAuthMethod({
          authSubjectId: args.emailOtpAuthSubjectId || `google:${args.nearAccountId}`,
        })
      : buildEcdsaRoleLocalPasskeyAuthMethod({
          credentialIdB64u: passkeyCredentialIdB64u,
          rpId,
        });
  const normalSigning = fixtureRouterAbEcdsaDerivationNormalSigning({
    walletId: args.nearAccountId,
    walletKeyId: evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    sessionId,
    clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    ethereumAddress,
  });
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: FIXTURE_ROLE_LOCAL_STATE_BLOB,
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId(args.nearAccountId),
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds,
      contextBinding32B64u: VALID_ECDSA_SHARE32_B64U,
      applicationBindingDigestB64u: VALID_ECDSA_SHARE32_B64U,
      derivationClientSharePublicKey33B64u: clientVerifyingShareB64u,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress,
      publicCapability: fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId: args.nearAccountId,
        sessionId,
        normalSigning,
      }),
    }),
    authMethod: roleLocalAuthMethod,
  });
  const roleLocalMaterialRef = buildEcdsaRoleLocalPersistedMaterialRefFixture({
    durableMaterialRef: `role-local:${sessionId}`,
    bindingDigest: ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
    materialOwner: args.nearAccountId,
  });
  const expiresAtMs = args.expiresAtMs ?? Date.now() + 120_000;
  const walletSessionToken = toFixtureWalletSessionToken(
    String(args.walletSessionToken || `opaque-wallet-session-token:ecdsa:${sessionId}`).trim(),
  );
  const activeWalletSession = parseActiveWalletSessionV1({
    kind: 'active_wallet_session_v1',
    walletId: requireBootstrapAuthorizationId(parseWalletId(args.nearAccountId)),
    authorityId: requireBootstrapAuthorizationId(
      parseWalletAuthorityId(`authority:ecdsa-bootstrap:${sessionId}`),
    ),
    authMethodId: requireBootstrapAuthorizationId(
      parseWalletAuthMethodId(`auth-method:ecdsa-bootstrap:${sessionId}`),
    ),
    authorizationId,
    quotaId,
    authorityDigestB64u: VALID_ECDSA_SHARE32_B64U,
    authorityRevocationEpoch: 0,
    capabilitySubjects: [
      {
        kind: 'sign',
        keyFamily: 'ecdsa_secp256k1',
        materialActivation: routerAbMpcMaterialActivationRefFromWire(
          ecdsaRoleLocalReadyRecord.publicFacts.publicCapability.material_activation,
        ),
      },
    ],
    issuedAtMs: Math.max(1, expiresAtMs - 60_000),
    expiresAtMs,
  });
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: walletSessionToken,
    walletSessionId,
  });

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
      chainTarget,
      relayerUrl,
      keyHandle,
      ecdsaThresholdKeyId,
      participantIds: [...participantIds],
      // Canonical passkey ECDSA session records may only reference durable
      // worker-owned role-local material; only the Email OTP branch still carries
      // a ready-state blob inline. Mirrors the production activation path.
      backendBinding:
        roleLocalAuthMethod.kind === 'email_otp'
          ? {
              materialKind: 'role_local_ready_state_blob',
              relayerKeyId,
              clientVerifyingShareB64u,
              stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
              ecdsaRoleLocalReadyRecord,
            }
          : {
              materialKind: 'role_local_worker_handle',
              relayerKeyId,
              clientVerifyingShareB64u,
              roleLocalMaterialHandle: {
                kind: 'ecdsa_role_local_worker_handle_v1',
                materialHandle: parseEcdsaRoleLocalMaterialHandle(`role-local-live:${sessionId}`),
                bindingDigest: parseEcdsaRoleLocalBindingDigest(
                  ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
                ),
                durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(
                  `role-local:${sessionId}`,
                ),
              },
              roleLocalMaterialRef,
              publicFacts: ecdsaRoleLocalReadyRecord.publicFacts,
              authMethod: ecdsaRoleLocalReadyRecord.authMethod,
            },
      routerAbEcdsaDerivationNormalSigning: normalSigning,
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
    },
    session: {
      ok: true,
      thresholdSessionId: sessionId,
      authorizationSessionId: requireBootstrapAuthorizationId(
        parseEcdsaAuthorizationSessionId(`ecdsa-bootstrap-authorization-session:${sessionId}`),
      ),
      authorizationId,
      walletSessionId,
      quotaId,
      expiresAtMs,
      remainingUses: args.remainingUses ?? 5,
      runtimePolicyScope,
      walletSession: activeWalletSession,
      operationCredential,
      walletSessionToken,
      clientVerifyingShareB64u,
    },
  };
}

export function thresholdEcdsaBootstrapPublicFactsFixture(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
) {
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  switch (binding.materialKind) {
    case 'role_local_worker_handle':
    case 'role_local_durable_sealed_ref':
    case 'role_local_durable_public_anchor':
      return binding.publicFacts;
    case 'role_local_ready_state_blob':
      return binding.ecdsaRoleLocalReadyRecord.publicFacts;
    case 'metadata_only':
      throw new Error('ECDSA bootstrap fixture requires role-local public facts');
    default:
      binding satisfies never;
      throw new Error('ECDSA bootstrap fixture has an unsupported material binding');
  }
}

export function createEcdsaSessionActivationFixture(args: {
  walletId: string;
  chain: ThresholdEcdsaActivationChain;
  sessionId?: string;
}) {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: args.walletId,
    chain: args.chain,
    sessionId: args.sessionId,
  });
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  const runtimePolicyScope = bootstrap.session.runtimePolicyScope;
  const walletSessionToken = bootstrap.session.walletSessionToken;
  const normalSigning = bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning;
  if (
    !binding ||
    binding.materialKind !== 'role_local_worker_handle' ||
    !runtimePolicyScope ||
    !walletSessionToken ||
    !normalSigning
  ) {
    throw new Error('ECDSA session activation fixture requires complete role-local material');
  }
  return {
    request: parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1({
      kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
      public_capability: binding.publicFacts.publicCapability,
      session_policy: {
        threshold_session_id: bootstrap.session.thresholdSessionId,
        wallet_session_mint_id: requireBootstrapAuthorizationId(
          parseWalletSessionMintId('wallet-session-mint-fixture'),
        ),
        ttl_ms: Math.max(1, bootstrap.session.expiresAtMs - Date.now()),
        remaining_uses: bootstrap.session.remainingUses,
        runtime_policy_scope: runtimePolicyScope,
      },
    }),
    response: parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1({
      kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
      public_capability: binding.publicFacts.publicCapability,
      session: {
        authorization_session_id: bootstrap.session.authorizationSessionId,
        authorization_id: bootstrap.session.authorizationId,
        threshold_session_id: bootstrap.session.thresholdSessionId,
        wallet_session_id: bootstrap.session.walletSessionId,
        quota_id: bootstrap.session.quotaId,
        expires_at_ms: bootstrap.session.expiresAtMs,
        remaining_uses: bootstrap.session.remainingUses,
        wallet_session: bootstrap.session.walletSession,
        operation_credential: bootstrap.session.operationCredential,
      },
      normal_signing: normalSigning,
    }),
  };
}

/**
 * Ready record behind a bootstrap fixture, for tests that need the role-local
 * material itself rather than the session record. Passkey bootstraps keep that
 * material worker-owned, so it is rebuilt from the handle's public facts instead
 * of being read off the backend binding.
 */
export function fixtureEcdsaRoleLocalReadyRecordFromBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): EcdsaRoleLocalReadyRecord {
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (binding?.materialKind === 'role_local_ready_state_blob') {
    return binding.ecdsaRoleLocalReadyRecord;
  }
  if (binding?.materialKind === 'role_local_worker_handle') {
    return buildEcdsaRoleLocalReadyRecord({
      stateBlob: FIXTURE_ROLE_LOCAL_STATE_BLOB,
      publicFacts: binding.publicFacts,
      authMethod: binding.authMethod,
    });
  }
  throw new Error('ECDSA bootstrap fixture does not carry role-local ready material');
}

function toFixtureWalletSessionToken(token: string): string {
  if (!token) throw new Error('ECDSA bootstrap fixture requires a Wallet Session token');
  if (/^wst_[A-Za-z0-9_-]{43}$/.test(token)) return token;
  return `wst_${Buffer.from(token).toString('base64url').padEnd(43, 'A').slice(0, 43)}`;
}

/** Converts a bootstrap fixture carrying an inline role-local ready-state blob
 * into the current worker-owned material binding: canonical passkey ECDSA
 * material is referenced through a durable worker handle, never carried inline.
 * Its previous home (`warmSessionTestServices.fixtures`) exercised the retired
 * composite record store and was deleted with it. */
export function toWorkerOwnedPasskeyEcdsaBootstrapFixture(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): ThresholdEcdsaSessionBootstrapResult {
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding || binding.materialKind !== 'role_local_ready_state_blob') {
    return bootstrap;
  }
  const sessionId = String(bootstrap.session.thresholdSessionId).trim() || 'fixture-session';
  const durableMaterialRef = parseEcdsaRoleLocalDurableMaterialRef(`role-local:${sessionId}`);
  const bindingDigest = parseEcdsaRoleLocalBindingDigest(
    binding.ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
  );
  const roleLocalMaterialRef = buildEcdsaRoleLocalPersistedMaterialRefFixture({
    durableMaterialRef,
    bindingDigest,
  });
  return {
    ...bootstrap,
    thresholdEcdsaKeyRef: {
      ...bootstrap.thresholdEcdsaKeyRef,
      backendBinding: {
        materialKind: 'role_local_worker_handle' as const,
        relayerKeyId: binding.relayerKeyId,
        clientVerifyingShareB64u: binding.clientVerifyingShareB64u,
        roleLocalMaterialHandle: {
          kind: 'ecdsa_role_local_worker_handle_v1' as const,
          materialHandle: parseEcdsaRoleLocalMaterialHandle(`role-local-live:${sessionId}`),
          bindingDigest,
          durableMaterialRef,
        },
        roleLocalMaterialRef,
        publicFacts: binding.ecdsaRoleLocalReadyRecord.publicFacts,
        authMethod: binding.ecdsaRoleLocalReadyRecord.authMethod,
      },
    },
  };
}
