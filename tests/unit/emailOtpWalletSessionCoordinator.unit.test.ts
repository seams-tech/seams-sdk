import { expect, test } from '@playwright/test';
import { IndexedDBManager } from '@/core/indexedDB';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import { type EmailOtpRoutePlan } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { parseRootShareEpoch, type RootShareEpoch } from '@shared/utils/domainIds';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentEcdsaSealedSessionRecordInput,
  type CurrentSealedSessionRecord,
  type listExactSealedSessionsForWallet,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  deriveEvmFamilyEcdsaKeyHandle,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdOwnerAddress,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { resolvedEvmFamilyEcdsaSigningLaneFromCandidate } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import { buildEmailOtpAuthContextForCanonicalWallet } from '@/core/signingEngine/session/identity/laneIdentity';
import { computeEcdsaDerivationRoleLocalThresholdKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { RestorePersistedSessionForSigningInput } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  createEcdsaSessionActivationFixture,
  fixtureRouterAbEcdsaDerivationPublicCapability,
} from './helpers/ecdsaBootstrap.fixtures';
import {
  buildEcdsaRoleLocalPersistedMaterialRefFixture,
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefForAuthorityFixture,
  buildWalletAuthAuthorityRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { resolveActiveEcdsaCapabilityRuntime } from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import {
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';

const TEST_SUBJECT_ID = toWalletId('alice.testnet');
const TEST_SIGNING_SESSION_SEAL_KEY_VERSION = parseSigningSessionSealKeyVersion(
  'signing-session-seal-kek-test-r1',
);
const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;

async function resolveMissingSelectedWalletAuthorityFixture(): Promise<ResolveSelectedWalletAuthorityResultV1> {
  return { kind: 'missing_selection' };
}

function installCanonicalAuthoritySelectionFixture(): void {
  IndexedDBManager.resolveSelectedWalletAuthority = resolveMissingSelectedWalletAuthorityFixture;
}

function restoreCanonicalAuthoritySelectionFixture(): void {
  IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
}

function emailOtpEcdsaUnlockWorkerResult(call: any) {
  const fixture = createEcdsaSessionActivationFixture({
    walletId: String(call.request.payload.walletId),
    chain: 'tempo',
    sessionId: 'ecdsa-session',
  });
  const material = call.request.payload.material;
  const requestedSessionPolicy = material?.ecdsaSessionPolicy;
  return {
    kind: 'ecdsa',
    operation: requestedSessionPolicy
      ? 'wallet_unlock'
      : material.ecdsaSessionHandleBinding.operation,
    recovery: {
      challengeId: 'challenge-1',
      enrollmentSealKeyVersion: 'email-v1',
      unlockChallengeId: 'unlock-challenge',
      unlockChallengeB64u: 'unlock-challenge-b64u',
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockSignatureB64u: 'unlock-signature',
    },
    emailOtpSessionHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
    ...(requestedSessionPolicy
      ? {
          ecdsaSession: {
            ...fixture.response,
            session: {
              ...fixture.response.session,
              threshold_session_id: requestedSessionPolicy.session_policy.threshold_session_id,
              remaining_uses: requestedSessionPolicy.session_policy.remaining_uses,
              expires_at_ms: Date.now() + requestedSessionPolicy.session_policy.ttl_ms,
            },
          },
        }
      : {}),
  };
}

function loginRoutePlan(): EmailOtpRoutePlan {
  return {
    routeFamily: 'login',
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  };
}

function ecdsaRestoreInput(args: {
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  authMethod?: 'email_otp' | 'passkey';
  walletId?: string;
  thresholdSessionId?: string;
  materialActivation?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['roleLocalMaterialRef']['materialActivation'];
  manifest?: ActiveEcdsaCapabilityManifest;
  providerSubjectId?: string;
}): Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }> {
  const walletId = args.walletId || String(args.manifest?.signer.walletId || 'alice.testnet');
  const wallet = toWalletId(walletId);
  const authMethod = args.authMethod || 'email_otp';
  const thresholdSessionId = args.thresholdSessionId || 'ecdsa-session';
  const publicFacts = args.manifest?.durableMaterial.roleLocalPublicFacts;
  const binding = args.manifest?.durableMaterial.roleLocalBinding;
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: wallet,
    ecdsaThresholdKeyId: String(binding?.ecdsaThresholdKeyId || 'ecdsa-key'),
    signingRootId: String(args.manifest?.signer.signingRootId || 'signing-root:dev'),
    signingRootVersion: String(args.manifest?.signer.signingRootVersion || 'root-v1'),
    participantIds: binding?.participantIds || [1, 2],
    thresholdOwnerAddress: toThresholdOwnerAddress(
      publicFacts?.ethereumAddress || `0x${'33'.repeat(20)}`,
    ),
  });
  const keyHandle = toEvmFamilyEcdsaKeyHandle(String(binding?.keyHandle || 'key-handle-ecdsa'));
  return {
    walletId,
    authMethod,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    thresholdSessionId,
    reason: 'transaction',
    materialRestoreIdentity: {
      kind: 'ecdsa_role_local_restore',
      lane: exactEcdsaSigningLaneIdentity({
        signer: buildEvmFamilyEcdsaSignerBinding({
          walletId: wallet,
          materialActivation:
            args.materialActivation ||
            args.manifest?.durableMaterial.materialActivation ||
            buildMpcMaterialActivationRefFixture(
              `restore:${walletId}:${thresholdSessionId}`,
              walletId,
            ),
          chainTarget: args.chainTarget,
          keyHandle,
          key,
        }),
        auth:
          authMethod === 'passkey'
            ? { kind: 'passkey', rpId: toRpId('example.com'), credentialIdB64u: 'credential-id' }
            : {
                kind: 'email_otp',
                providerSubjectId: args.providerSubjectId || 'google:subject',
              },
      }),
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    },
  };
}

const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
const TEST_WALLET_SESSION = walletSessionRefFromSession({
  walletId: 'alice.testnet',
  walletSessionUserId: 'alice.testnet',
});
const VALID_ECDSA_PUBLIC_KEY_B64U = Buffer.from(new Uint8Array([2, ...Array(32).fill(1)])).toString(
  'base64url',
);
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = Buffer.from(
  new Uint8Array([2, ...Array(32).fill(2)]),
).toString('base64url');
const VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U = Buffer.from(
  new Uint8Array([2, ...Array(32).fill(3)]),
).toString('base64url');
const VALID_ECDSA_PRIVATE_SHARE_B64U = Buffer.from(new Uint8Array(32).fill(4)).toString(
  'base64url',
);
const VALID_ECDSA_CONTEXT_BINDING_B64U = Buffer.from(new Uint8Array(32).fill(5)).toString(
  'base64url',
);
const VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U = Buffer.from(
  new Uint8Array(32).fill(6),
).toString('base64url');

function emailOtpAuthContextFixture(
  args: {
    policy?: 'session' | 'per_operation';
    retention?: 'session' | 'single_use';
    reason?: 'login' | 'sign';
    walletId?: string;
    providerUserId?: string;
    emailHashHex?: string;
  } = {},
) {
  const retention = args.retention || 'session';
  const walletId = args.walletId || TEST_SUBJECT_ID;
  const emailHashHex = args.emailHashHex || 'email-hash';
  if (retention === 'single_use') {
    return buildEmailOtpAuthContextForCanonicalWallet({
      policy: args.policy || 'per_operation',
      // 'retention' became required; omitting it built the same pending
      // single-use context this branch selects.
      retention: 'single_use',
      walletId,
      provider: 'google',
      providerUserId: args.providerUserId || 'google:subject',
      emailHashHex,
    });
  }
  return buildEmailOtpAuthContextForCanonicalWallet({
    policy: args.policy || 'session',
    retention: 'session',
    reason: args.reason || 'login',
    walletId,
    provider: 'google',
    providerUserId: args.providerUserId || 'google:subject',
    emailHashHex,
  });
}

type RuntimePolicyScopeFixture = NonNullable<
  BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['runtimePolicyScope']
>;

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function makeEmailOtpRoleLocalReadyRecord(args: {
  walletId: string;
  rpId: string;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  keyHandle: string;
  evmFamilySigningKeySlotId?: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
  thresholdSessionId: string;
}) {
  const evmFamilySigningKeySlotId =
    args.evmFamilySigningKeySlotId ||
    deriveEvmFamilySigningKeySlotId({
      walletId: args.walletId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
    });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_ECDSA_PRIVATE_SHARE_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId(args.walletId),
      chainTarget: args.chainTarget,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      applicationBindingDigestB64u: VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U,
      contextBinding32B64u: VALID_ECDSA_CONTEXT_BINDING_B64U,
      derivationClientSharePublicKey33B64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress: args.ethereumAddress,
      publicCapability: fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId: args.walletId,
        sessionId: args.thresholdSessionId,
        normalSigning: routerAbEcdsaDerivationNormalSigningFixture({
          walletId: args.walletId,
          evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
          signingRootId: args.signingRootId,
          signingRootVersion: args.signingRootVersion,
          ethereumAddress: args.ethereumAddress,
          thresholdSessionId: args.thresholdSessionId,
        }),
      }),
    }),
    authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
      authSubjectId: args.walletId,
    }),
  });
}
function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    sub: 'google:subject',
    provider: 'google',
    providerSubject: 'google:subject',
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: 'google:subject',
    },
    walletId: TEST_WALLET_SESSION.walletId,
    exp: expSeconds,
  })}.sig`;
}

function signingRootFromRuntimePolicyScope(
  runtimePolicyScope:
    | { projectId?: unknown; envId?: unknown; signingRootVersion?: unknown }
    | null
    | undefined,
): { signingRootId: string; signingRootVersion: string } {
  const projectId = String(runtimePolicyScope?.projectId || '').trim();
  const envId = String(runtimePolicyScope?.envId || '').trim();
  const signingRootVersion = String(runtimePolicyScope?.signingRootVersion || '').trim();
  if (!projectId || !envId || !signingRootVersion) {
    return { signingRootId: 'signing-root', signingRootVersion: 'root-v1' };
  }
  return {
    signingRootId: `${projectId}:${envId}`,
    signingRootVersion,
  };
}

function emailOtpEcdsaClientRootHandleFromWorkerCall(call: any) {
  const binding = call.request?.payload?.ecdsaClientRootHandleBinding;
  const walletId = call.request?.payload?.walletId || 'alice.testnet';
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: 'email-otp-ecdsa-root-test',
    walletId,
    keyHandle:
      binding?.keyHandle || call.request?.payload?.restore?.keyHandle || 'key-handle-ecdsa',
    authSubjectId: binding?.authSubjectId || call.request?.payload?.userId || 'alice.testnet',
    action: 'threshold_ecdsa_bootstrap',
    operation: binding?.operation || 'wallet_unlock',
    chainTarget: binding?.chainTarget || TEMPO_CHAIN_TARGET,
  };
}

async function absentWalletCustodyEd25519Material() {
  return { kind: 'absent' as const };
}

async function noopRestoreWalletCustodyEcdsaContinuity(): Promise<unknown> {
  return {};
}

function hexAddress20B64u(address: `0x${string}`): string {
  const hex = address.replace(/^0x/, '');
  if (hex.length !== 40) {
    throw new Error(`invalid ECDSA address fixture: ${address}`);
  }
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    const hexByte = hex.slice(index * 2, index * 2 + 2);
    const value = Number.parseInt(hexByte, 16);
    if (!Number.isFinite(value)) {
      throw new Error(`invalid ECDSA address fixture: ${address}`);
    }
    bytes[index] = value;
  }
  return Buffer.from(bytes).toString('base64url');
}

/** Brands a fixture activation epoch via the production parser. */
function fixtureRootShareEpoch(value: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) {
    throw new Error(`invalid fixture activation epoch: ${value}`);
  }
  return parsed.value;
}

function routerAbEcdsaDerivationNormalSigningFixture(args: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
  thresholdSessionId: string;
  clientVerifyingShareB64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const clientPublicKey33B64u = args.clientVerifyingShareB64u || VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U;
  const thresholdPublicKey33B64u = args.thresholdEcdsaPublicKeyB64u || VALID_ECDSA_PUBLIC_KEY_B64U;
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: args.signingRootId,
      signing_root_version: args.signingRootVersion,
      context: {
        application_binding_digest_b64u: VALID_ECDSA_APPLICATION_BINDING_DIGEST_B64U,
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_CONTEXT_BINDING_B64U,
        derivation_client_share_public_key33_b64u: clientPublicKey33B64u,
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: thresholdPublicKey33B64u,
        ethereum_address20_b64u: hexAddress20B64u(args.ethereumAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(
        buildMpcMaterialActivationRefFixture(
          `email-otp:${args.walletId}:${args.ecdsaThresholdKeyId}:${args.thresholdSessionId}`,
          args.walletId,
        ),
      ),
      signing_worker: {
        server_id: 'signing-worker-test',
        key_epoch: 'worker-epoch-test',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: fixtureRootShareEpoch(args.thresholdSessionId),
    },
  };
}

function emailOtpWorkerBackendBindingFixture(args: {
  walletId: string;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  keyHandle: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  ethereumAddress: `0x${string}`;
  thresholdSessionId: string;
}) {
  const readyRecord = makeEmailOtpRoleLocalReadyRecord({
    walletId: args.walletId,
    rpId: 'localhost',
    chainTarget: args.chainTarget,
    keyHandle: args.keyHandle,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
    ethereumAddress: args.ethereumAddress,
    thresholdSessionId: args.thresholdSessionId,
  });
  const durableMaterialRef = `role-local-durable-${args.thresholdSessionId}`;
  return {
    materialKind: 'role_local_worker_handle' as const,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    roleLocalMaterialHandle: {
      kind: 'ecdsa_role_local_worker_handle_v1' as const,
      materialHandle: `${durableMaterialRef}:live`,
      bindingDigest: readyRecord.publicFacts.contextBinding32B64u,
      durableMaterialRef,
    },
    roleLocalMaterialRef: buildEcdsaRoleLocalPersistedMaterialRefFixture({
      durableMaterialRef,
      bindingDigest: readyRecord.publicFacts.contextBinding32B64u,
      label: `email-otp-worker:${args.thresholdSessionId}`,
      materialOwner: args.walletId,
    }),
    publicFacts: readyRecord.publicFacts,
    authMethod: readyRecord.authMethod,
  };
}

function emailOtpProvisionedEcdsaBootstrapFixture(args: {
  request: any;
  chainTarget: ReturnType<typeof thresholdEcdsaChainTargetFromChainFamily>;
  sessionAuthority: {
    authorizationSessionId: string;
    walletSessionId: string;
    quotaId: string;
  };
  remainingUses?: number;
}) {
  const request = args.request;
  const walletId = request.walletKey?.walletId || 'alice.testnet';
  const thresholdSessionId = request.lanePolicy?.thresholdSessionId || 'ecdsa-session';
  const keyHandle = request.walletKey?.keyHandle || 'key-handle-ecdsa';
  const ecdsaThresholdKeyId = 'ecdsa-key';
  const runtimePolicyScope = request.runtimePolicy?.scope || request.lanePolicy?.runtimePolicyScope;
  const signingRootId =
    runtimePolicyScope?.projectId && runtimePolicyScope?.envId
      ? `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`
      : 'signing-root';
  const signingRootVersion = runtimePolicyScope?.signingRootVersion || 'root-v1';
  const ethereumAddress = `0x${'33'.repeat(20)}` as `0x${string}`;
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: toWalletId(walletId),
    signingRootId,
    signingRootVersion,
  });
  const routerAbEcdsaDerivationNormalSigning = routerAbEcdsaDerivationNormalSigningFixture({
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    ethereumAddress,
    thresholdSessionId,
  });
  const walletSessionToken = `opaque-wallet-session-token:ecdsa:${thresholdSessionId}`;
  const remainingUses = args.remainingUses ?? 3;
  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: walletId,
      relayerUrl: request.relayerUrl || 'https://relay.example',
      keyHandle,
      ecdsaThresholdKeyId,
      chainTarget: args.chainTarget,
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      participantIds: [1, 3],
      routerAbEcdsaDerivationNormalSigning,
      backendBinding: emailOtpWorkerBackendBindingFixture({
        walletId,
        chainTarget: args.chainTarget,
        keyHandle,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        ethereumAddress,
        thresholdSessionId,
      }),
    },
    session: {
      ok: true,
      thresholdSessionId,
      authorizationSessionId: args.sessionAuthority.authorizationSessionId,
      walletSessionId: args.sessionAuthority.walletSessionId,
      quotaId: args.sessionAuthority.quotaId,
      expiresAtMs:
        request.preauthorizedSessionActivation?.session?.expires_at_ms || Date.now() + 60_000,
      remainingUses,
      runtimePolicyScope,
      walletSessionToken,
      clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    },
  };
}

async function roleLocalEcdsaKeyHandle(args: {
  walletId: string;
  rpId: string;
  projectId: string;
  envId: string;
  signingRootVersion: string;
}): Promise<string> {
  const signingRootId = `${args.projectId}:${args.envId}`;
  const walletKeyId = `wallet-key-${args.walletId}-${args.projectId}-${args.envId}`;
  const ecdsaThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId(
    // Cast: this fixture predates the walletKeyId -> evmFamilySigningKeySlotId
    // rename. Renaming the fact would change the derived digest these
    // WIP-classified tests exercise at runtime, so the stale shape is kept as-is.
    {
      walletId: args.walletId,
      walletKeyId,
      signingRootId,
      signingRootVersion: args.signingRootVersion,
    } as unknown as Parameters<typeof computeEcdsaDerivationRoleLocalThresholdKeyId>[0],
  );
  return String(
    await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion: args.signingRootVersion,
    }),
  );
}

/** The Email OTP arm of the sealed ECDSA restore union used by this fixture. */
type EmailOtpJwtEcdsaSealedRestore = Extract<
  BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore'],
  { source: 'email_otp' }
>;

type EcdsaSealedRecordFixtureArgs = {
  expiresAtMs: number;
  thresholdSessionId?: string;
  thresholdSessionIds?: BuildCurrentEcdsaSealedSessionRecordInput['thresholdSessionIds'];
  walletId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  groupId?: BuildCurrentEcdsaSealedSessionRecordInput['groupId'];
  sealedSecretB64u?: string;
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  ecdsaRestore?: Partial<EmailOtpJwtEcdsaSealedRestore>;
  issuedAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
};

function buildEcdsaSealedRecordFixture(
  args: EcdsaSealedRecordFixtureArgs,
): Extract<CurrentSealedSessionRecord, { curve: 'ecdsa' }> {
  const chainTarget = args.ecdsaRestore?.chainTarget || args.chainTarget || TEMPO_CHAIN_TARGET;
  const thresholdSessionId =
    args.thresholdSessionId || args.thresholdSessionIds?.ecdsa || 'ecdsa-session';
  const walletId = args.walletId || 'alice.testnet';
  const keyHandle = args.ecdsaRestore?.keyHandle || 'key-handle-ecdsa';
  const signingRootId = args.signingRootId || 'signing-root:dev';
  const signingRootParts = signingRootId.includes(':')
    ? signingRootId.split(':')
    : [signingRootId, 'dev'];
  const runtimePolicyScope = {
    orgId: 'org-test',
    projectId: signingRootParts[0] || 'signing-root',
    envId: signingRootParts[1] || 'dev',
    signingRootVersion: args.signingRootVersion || 'root-v1',
  };
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: toWalletId(walletId),
    signingRootId,
    signingRootVersion: args.signingRootVersion || 'root-v1',
  });
  const routerAbEcdsaDerivationNormalSigning =
    args.ecdsaRestore?.routerAbEcdsaDerivationNormalSigning ||
    routerAbEcdsaDerivationNormalSigningFixture({
      walletId,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: args.ecdsaRestore?.ecdsaThresholdKeyId || 'ecdsa-key',
      signingRootId,
      signingRootVersion: args.signingRootVersion || 'root-v1',
      ethereumAddress: (args.ecdsaRestore?.ethereumAddress ||
        `0x${'33'.repeat(20)}`) as `0x${string}`,
      thresholdSessionId,
    });
  const emailOtpAuthority = buildEmailOtpWalletAuthAuthority({
    walletId,
    provider: args.ecdsaRestore?.provider || 'google',
    providerUserId: args.ecdsaRestore?.providerSubjectId || 'google:subject',
    emailHashHex: args.ecdsaRestore?.emailHashHex || 'email-hash',
  });
  const ecdsaRestore = {
    chainTarget,
    source: 'email_otp',
    provider: args.ecdsaRestore?.provider || 'google',
    signingRootId,
    signingRootVersion: args.signingRootVersion || 'root-v1',
    providerSubjectId: args.ecdsaRestore?.providerSubjectId || 'google:subject',
    emailHashHex: args.ecdsaRestore?.emailHashHex || 'email-hash',
    authority: buildWalletAuthAuthorityRefForAuthorityFixture(emailOtpAuthority),
    emailOtpAuthority,
    keyHandle,
    ecdsaThresholdKeyId: args.ecdsaRestore?.ecdsaThresholdKeyId || 'ecdsa-key',
    ethereumAddress: args.ecdsaRestore?.ethereumAddress || `0x${'33'.repeat(20)}`,
    relayerKeyId: args.ecdsaRestore?.relayerKeyId || 'relayer-key',
    clientVerifyingShareB64u:
      args.ecdsaRestore?.clientVerifyingShareB64u || VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    thresholdEcdsaPublicKeyB64u:
      args.ecdsaRestore?.thresholdEcdsaPublicKeyB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
    participantIds: args.ecdsaRestore?.participantIds || [1, 2],
    routerAbEcdsaDerivationNormalSigning,
    roleLocalMaterialRef:
      args.ecdsaRestore?.roleLocalMaterialRef ||
      buildEcdsaRoleLocalPersistedMaterialRefFixture({
        durableMaterialRef: `role-local:email-otp-coordinator:${thresholdSessionId}`,
        bindingDigest:
          routerAbEcdsaDerivationNormalSigning.scope.public_identity.context_binding_b64u,
        label: `email-otp-coordinator:${thresholdSessionId}`,
        materialOwner: walletId,
      }),
    publicCapability:
      args.ecdsaRestore?.publicCapability ||
      fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId,
        sessionId: routerAbEcdsaDerivationNormalSigning.scope.activation_epoch,
        normalSigning: routerAbEcdsaDerivationNormalSigning,
      }),
    runtimePolicyScope: args.ecdsaRestore?.runtimePolicyScope || runtimePolicyScope,
  } as EmailOtpJwtEcdsaSealedRestore;
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    walletId,
    relayerUrl: args.relayerUrl || 'https://relay.example',
    keyVersion: args.keyVersion || 'signing-session-seal-kek-test-r1',
    groupId: args.groupId || 'rfc2409-group2',
    thresholdSessionId,
    thresholdSessionIds: args.thresholdSessionIds || { ecdsa: thresholdSessionId },
    sealedSecretB64u: args.sealedSecretB64u || 'sealed-session-secret',
    ecdsaRestore,
    issuedAtMs: args.issuedAtMs || Date.now(),
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses ?? 2,
    updatedAtMs: args.updatedAtMs || Date.now(),
  });
  if (!record || record.curve !== 'ecdsa') {
    throw new Error('invalid ECDSA sealed session fixture');
  }
  return record;
}

function createCoordinator(overrides?: {
  requestWorkerOperation?: (call: any) => Promise<any>;
  getRpId?: () => string | null;
  configs?: Record<string, any>;
  writeExactSealedSession?: (args: any) => Promise<void>;
  readExactSealedSession?: (thresholdSessionId: string, purpose?: any) => Promise<any>;
  listExactSealedSessionsForWallet?: typeof listExactSealedSessionsForWallet;
  provisionThresholdEcdsaSession?: (request: any) => Promise<any>;
  provisionEmailOtpEcdsaExplicitExportSession?: (request: any) => Promise<any>;
  acquireSigningSessionRestoreLease?: (args: any) => Promise<any>;
  releaseSigningSessionRestoreLease?: (lease: any) => Promise<void>;
  readActiveWalletSessionAuthorization?: () => Promise<any>;
  listActiveEcdsaCapabilityManifestsForWallet?: () => Promise<
    readonly ActiveEcdsaCapabilityManifest[]
  >;
  resolveCurrentEcdsaCapabilityRuntime?: typeof resolveActiveEcdsaCapabilityRuntime;
}) {
  const thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
  const workerCalls: any[] = [];
  const ecdsaProvisionCalls: any[] = [];
  let ecdsaSessionAuthority: {
    authorizationSessionId: string;
    walletSessionId: string;
    quotaId: string;
  } | null = null;
  const worker = {
    requestWorkerOperation: async (call: any) => {
      workerCalls.push(call);
      if (overrides?.requestWorkerOperation) {
        return overrides.requestWorkerOperation(call);
      }
      if (call.request?.type === 'requestEmailOtpChallenge') {
        return {
          challengeId: 'challenge-1',
          delivery: {
            kind: 'provider',
            status: 'sent',
            emailHint: 'a***@example.com',
          },
        };
      }
      if (call.request?.type === 'loginWithEmailOtpWallet') {
        return emailOtpEcdsaUnlockWorkerResult(call);
      }
      if (call.request?.type === 'exportThresholdEcdsaDerivationKeyWithEmailOtpAuthorization') {
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: '11'.repeat(32),
          ethereumAddress: '0x'.padEnd(42, 'a'),
        };
      }
      if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
        return {
          ok: true,
          sealedSecretB64u: 'sealed-email-otp-session-secret',
          keyVersion: 'signing-session-seal-kek-test-r1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        };
      }
      if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
          emailOtpSessionHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
        };
      }
      if (call.request?.type === 'enrollEmailOtpWallet') {
        return {
          thresholdEcdsaClientVerifyingShareB64u: 'verifying-share',
          challengeId: call.request.payload.challengeId,
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: 'email-v1',
          clientUnlockPublicKeyB64u: 'unlock-public',
          unlockKeyVersion: 'unlock-v1',
        };
      }
      return { ok: true };
    },
  };
  const ecdsaCommitCalls: any[] = [];
  const sealedRecordWrites: CurrentSealedSessionRecord[] = [];
  const toSealedRecordReadback = (record: CurrentSealedSessionRecord): CurrentSealedSessionRecord =>
    record;
  const recordMatchesSealedPurpose = (
    write: any,
    thresholdSessionId: string | undefined,
    purpose?: any,
  ) => {
    if (thresholdSessionId && write.thresholdSessionIds?.ecdsa !== thresholdSessionId) {
      return false;
    }
    if (purpose?.authMethod && write.authMethod !== purpose.authMethod) return false;
    if (purpose?.curve && write.curve !== purpose.curve) return false;
    if (
      purpose?.chainTarget &&
      (!write.ecdsaRestore?.chainTarget ||
        !thresholdEcdsaChainTargetsEqual(write.ecdsaRestore.chainTarget, purpose.chainTarget))
    ) {
      return false;
    }
    return true;
  };
  const defaultReadExactSealedSession = async (thresholdSessionId: string, purpose?: any) => {
    const record = sealedRecordWrites.find((write) =>
      recordMatchesSealedPurpose(write, thresholdSessionId, purpose),
    );
    return record ? toSealedRecordReadback(record) : null;
  };
  const defaultListExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet = async ({
    walletId,
    filter,
  }) =>
    sealedRecordWrites
      .filter((write) => {
        // Cast: stale-shape compatibility read; current sealed records no longer
        // carry userId, so this clause is a no-op kept for byte-identical runtime.
        if (write.walletId !== walletId && (write as { userId?: string }).userId !== walletId) {
          return false;
        }
        return recordMatchesSealedPurpose(write, undefined, filter);
      })
      .map(toSealedRecordReadback);
  const baseConfigs = {
    registration: {
      mode: 'managed',
      projectEnvironmentId: 'env_test',
      publishableKey: 'pk_test',
    },
    network: {
      relayer: { url: 'https://relay.example' },
      chains: [
        {
          network: 'tempo-testnet',
          rpcUrl: 'https://rpc.tempo.test',
          explorerUrl: 'https://explorer.tempo.test',
          chainId: 42431,
        },
        {
          network: 'arc-testnet',
          rpcUrl: 'https://rpc.arc.test',
          explorerUrl: 'https://explorer.arc.test',
          chainId: 5042002,
        },
      ],
    },
    signing: {
      emailOtp: { authPolicy: 'per_operation' },
      routerAb: {
        normalSigning: {
          mode: 'enabled',
          signingWorkerId: 'local-signing-worker',
        },
      },
      sessionPersistenceMode: 'none',
      sessionSeal: {
        mode: 'sealed_refresh_v1',
        protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
      },
    },
  };
  const coordinator = new EmailOtpWalletSessionCoordinator({
    configs: {
      ...baseConfigs,
      ...(overrides?.configs || {}),
      registration: {
        ...baseConfigs.registration,
        ...(overrides?.configs?.registration || {}),
      },
      network: {
        ...baseConfigs.network,
        ...(overrides?.configs?.network || {}),
      },
      signing: {
        ...baseConfigs.signing,
        ...(overrides?.configs?.signing || {}),
        emailOtp: {
          ...baseConfigs.signing.emailOtp,
          ...(overrides?.configs?.signing?.emailOtp || {}),
        },
        routerAb: {
          ...baseConfigs.signing.routerAb,
          ...(overrides?.configs?.signing?.routerAb || {}),
          normalSigning: {
            ...baseConfigs.signing.routerAb.normalSigning,
            ...(overrides?.configs?.signing?.routerAb?.normalSigning || {}),
          },
        },
        sessionSeal: {
          ...baseConfigs.signing.sessionSeal,
          ...(overrides?.configs?.signing?.sessionSeal || {}),
        },
      },
    } as any,
    signerWorkerManager: worker as any,
    getRpId: overrides?.getRpId || (() => 'localhost'),
    getSignerWorkerContext: () => worker as any,
    loadWalletCustodyEd25519Material: absentWalletCustodyEd25519Material,
    restoreWalletCustodyEcdsaContinuity: noopRestoreWalletCustodyEcdsaContinuity,
    withThresholdEcdsaSigningQueue: (args) =>
      withThresholdEcdsaSigningQueue({
        queueByKey: thresholdEcdsaSigningQueueByKey,
        ...args,
      }),
    readActiveWalletSessionAuthorization:
      overrides?.readActiveWalletSessionAuthorization ||
      (async () => ({
        kind: 'found',
        projection: activeEvmFamilyWalletSessionAuthorizationFixture({
          walletId: TEST_SUBJECT_ID,
          authority: buildWalletAuthAuthorityRefFixture({ walletId: TEST_SUBJECT_ID }),
          authMethod: 'email_otp',
        }).projection,
      })),
    commitEvmFamilyThresholdEcdsaSessions: async (args) => {
      ecdsaCommitCalls.push(args);
      return {
        bootstrap: args.bootstrap,
        authorization: activeEvmFamilyWalletSessionAuthorizationFixture({
          walletId: TEST_SUBJECT_ID,
          authority: buildWalletAuthAuthorityRefFixture({ walletId: TEST_SUBJECT_ID }),
        }).projection,
      };
    },
    listActiveEcdsaCapabilityManifestsForWallet:
      overrides?.listActiveEcdsaCapabilityManifestsForWallet ||
      (async () => {
        const runtimePolicyScope = {
          projectId: 'proj',
          envId: 'dev',
          signingRootVersion: 'v1',
        };
        const keyHandle = await roleLocalEcdsaKeyHandle({
          walletId: String(TEST_SUBJECT_ID),
          rpId: 'localhost',
          projectId: runtimePolicyScope.projectId,
          envId: runtimePolicyScope.envId,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        });
        return [await emailOtpLoginManifestFixture({ runtimePolicyScope, keyHandle })];
      }),
    resolveCurrentEcdsaCapabilityRuntime:
      overrides?.resolveCurrentEcdsaCapabilityRuntime || resolveActiveEcdsaCapabilityRuntime,
    provisionThresholdEcdsaSession:
      overrides?.provisionThresholdEcdsaSession ||
      (async (request: any) => {
        ecdsaProvisionCalls.push(request);
        const lanePolicy = request?.lanePolicy || {};
        const activatedSession = request.preauthorizedSessionActivation?.session;
        if (activatedSession) {
          ecdsaSessionAuthority = {
            authorizationSessionId: activatedSession.authorization_session_id,
            walletSessionId: activatedSession.wallet_session_id,
            quotaId: activatedSession.quota_id,
          };
        }
        ecdsaSessionAuthority ||= {
          authorizationSessionId: 'authorization-session',
          walletSessionId: 'wallet-session',
          quotaId: 'wallet-signing-quota',
        };
        const bootstrap = emailOtpProvisionedEcdsaBootstrapFixture({
          request,
          chainTarget: lanePolicy.chainTarget,
          sessionAuthority: ecdsaSessionAuthority,
        });
        const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
        if (!backendBinding || backendBinding.materialKind !== 'role_local_worker_handle') {
          throw new Error('test provisionThresholdEcdsaSession expected worker-owned material');
        }
        return {
          ...bootstrap,
          thresholdEcdsaKeyRef: {
            ...bootstrap.thresholdEcdsaKeyRef,
            backendBinding: {
              ...backendBinding,
              publicFacts: request.existingRoleLocalMaterial.publicFacts,
              roleLocalMaterialRef: {
                ...backendBinding.roleLocalMaterialRef,
                materialActivation: request.existingRoleLocalMaterial.materialActivation,
              },
            },
          },
        };
      }),
    provisionEmailOtpEcdsaExplicitExportSession:
      overrides?.provisionEmailOtpEcdsaExplicitExportSession ||
      (async () => {
        throw new Error(
          'test provisionEmailOtpEcdsaExplicitExportSession is not wired for this scenario',
        );
      }),
    writeExactSealedSession: async (args) => {
      sealedRecordWrites.push(args);
      if (overrides?.writeExactSealedSession) {
        await overrides.writeExactSealedSession(args);
      }
    },
    readExactSealedSession: overrides?.readExactSealedSession || defaultReadExactSealedSession,
    listExactSealedSessionsForWallet:
      overrides?.listExactSealedSessionsForWallet || defaultListExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease:
      overrides?.acquireSigningSessionRestoreLease || (async () => null),
    releaseSigningSessionRestoreLease:
      overrides?.releaseSigningSessionRestoreLease || (async () => {}),
    deleteDurableSealedSessionRecord: async () => {},
    updateExactSealedSessionPolicy: async () => {},
  });

  return {
    coordinator,
    workerCalls,
    ecdsaProvisionCalls,
    ecdsaCommitCalls,
    sealedRecordWrites,
  };
}

async function emailOtpLoginManifestFixture(args: {
  runtimePolicyScope: {
    projectId: string;
    envId: string;
    signingRootVersion: string;
  };
  keyHandle: string;
}): Promise<ActiveEcdsaCapabilityManifest> {
  return (
    await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp', {
      walletId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      targetMemberships: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET],
      keyHandle: args.keyHandle,
      signingRootId: `${args.runtimePolicyScope.projectId}:${args.runtimePolicyScope.envId}`,
      signingRootVersion: args.runtimePolicyScope.signingRootVersion,
      authority: buildEmailOtpWalletAuthAuthority({
        walletId: TEST_SUBJECT_ID,
        provider: 'google',
        providerUserId: 'google:subject',
        emailHashHex: 'email-hash',
      }),
    })
  ).manifest;
}

test.describe('EmailOtpWalletSessionCoordinator', () => {
  test.beforeAll(installCanonicalAuthoritySelectionFixture);
  test.afterAll(restoreCanonicalAuthoritySelectionFixture);

  test('normalizes warm-session status requests and maps worker failures', async () => {
    const invalid = createCoordinator();
    await expect(
      invalid.coordinator.readWarmSessionStatusOnly({
        kind: 'ecdsa',
        thresholdSessionId: '   ',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_args',
    });
    expect(invalid.workerCalls).toHaveLength(0);

    const failing = createCoordinator({
      requestWorkerOperation: async () => {
        throw new Error('worker unavailable');
      },
    });
    await expect(
      failing.coordinator.readWarmSessionStatusOnly({
        kind: 'ecdsa',
        thresholdSessionId: ' session-1 ',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
      message: 'worker unavailable',
    });
    expect(failing.workerCalls[0].request.payload.target).toEqual({
      kind: 'ecdsa',
      thresholdSessionId: 'session-1',
    });
  });

  test('requests transaction challenges with signing-session auth only', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const walletSessionToken = 'threshold-session-token';

    const challenge = await coordinator.requestTransactionSigningChallenge({
      kind: 'near_account_challenge',
      walletSession: TEST_WALLET_SESSION,
      nearAccountId: 'alice.testnet',
      chain: 'near',
      authLane: {
        kind: 'signing_session',
        walletSessionToken,
        curve: 'ed25519',
      },
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              walletSessionToken,
              curve: 'ed25519',
            },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('requests ECDSA export challenges through the wallet login route', async () => {
    const { coordinator, workerCalls } = createCoordinator();

    const challenge = await coordinator.requestExportChallenge({
      kind: 'wallet_login_challenge',
      walletSession: TEST_WALLET_SESSION,
      chain: TEMPO_CHAIN_TARGET.kind,
    });

    expect(challenge.challengeId).toBe('challenge-1');
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'login',
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('transaction challenges reject missing signing-session authority', async () => {
    const { coordinator, workerCalls } = createCoordinator();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: TEST_WALLET_SESSION,
        nearAccountId: 'alice.testnet',
        chain: 'near',
      } as never),
    ).rejects.toThrow(
      'Email OTP ed25519 signing-session auth lane is unavailable at provided_route_auth',
    );

    expect(workerCalls).toHaveLength(0);
  });

  test('transaction challenges reject app-session route auth instead of resolving it', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        walletSession: TEST_WALLET_SESSION,
        nearAccountId: 'alice.testnet',
        chain: 'near',
        routeAuth: { kind: 'app_session', jwt },
      } as never),
    ).rejects.toThrow(
      'Email OTP ed25519 signing-session auth lane is unavailable at provided_route_auth',
    );

    expect(workerCalls).toHaveLength(0);
  });

  test('logs in ECDSA Email OTP capability with normalized worker payload and persistence callback', async () => {
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });
    const manifest = await emailOtpLoginManifestFixture({ runtimePolicyScope, keyHandle });
    const { coordinator, workerCalls, ecdsaCommitCalls, ecdsaProvisionCalls } = createCoordinator({
      listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
    });
    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      authoritySelector: { kind: 'wallet' },
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlan(),
      keyHandle,
      participantIds: [1, 3],
      runtimePolicyScope,
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      providerIdentity: {
        kind: 'explicit_provider_user',
        provider: 'google',
        providerUserId: 'google:subject',
      },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    const loginCall = workerCalls.find((call) => call.request?.type === 'loginWithEmailOtpWallet');
    expect(loginCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpWallet',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          verification: {
            kind: 'otp',
            challengeId: 'challenge-1',
            otpCode: '123456',
          },
          routePlan: {
            routeFamily: 'login',
            operation: 'wallet_unlock',
          },
        },
      },
    });
    expect(loginCall?.request?.payload?.material?.ed25519YaoRecovery).toBeUndefined();
    expect(ecdsaProvisionCalls[0]).toMatchObject({
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      sessionKind: 'opaque',
      sessionBudgetUses: 3,
      runtimePolicy: {
        kind: 'scoped_policy',
        scope: manifest.durableMaterial.runtimePolicyScope,
      },
      preauthorizedSessionActivation: {
        session: {
          threshold_session_id: result.bootstrap.session.thresholdSessionId,
          remaining_uses: result.bootstrap.session.remainingUses,
        },
      },
      walletKey: {
        walletId: 'alice.testnet',
        keyHandle,
        keyFacts: {
          keyScope: 'evm-family',
          signingRootId: manifest.signer.signingRootId,
          signingRootVersion: manifest.signer.signingRootVersion,
          participantIds: manifest.signer.registeredPublicFacts.participantIds,
        },
      },
      lanePolicy: {
        chainTarget: TEMPO_CHAIN_TARGET,
        thresholdSessionId: result.bootstrap.session.thresholdSessionId,
        remainingUses: 3,
      },
    });
    expect(ecdsaProvisionCalls[0]).not.toHaveProperty('walletSessionRouteAuth');
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      chainTarget: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: emailOtpAuthContextFixture(),
    });
    expect(result).not.toHaveProperty('ed25519Reconstruction');
  });

  test('wallet unlock adopts its prepared ECDSA session without replaying app-session auth', async () => {
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });
    const manifest = await emailOtpLoginManifestFixture({ runtimePolicyScope, keyHandle });
    const { coordinator, ecdsaProvisionCalls } = createCoordinator({
      listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
    });
    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      authoritySelector: { kind: 'wallet' },
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlan(),
      keyHandle,
      participantIds: [1, 3],
      runtimePolicyScope,
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      providerIdentity: {
        kind: 'explicit_provider_user',
        provider: 'google',
        providerUserId: 'google:subject',
      },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(ecdsaProvisionCalls[0]).toMatchObject({
      source: 'email_otp',
      preauthorizedSessionActivation: {
        session: {
          threshold_session_id: expect.any(String),
        },
      },
    });
    expect(ecdsaProvisionCalls[0]).not.toHaveProperty('walletSessionRouteAuth');
  });

  test('ECDSA Email OTP login resolves runtime scope from the exact durable manifest', async () => {
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });
    const manifest = await emailOtpLoginManifestFixture({ runtimePolicyScope, keyHandle });
    const { coordinator, ecdsaProvisionCalls } = createCoordinator({
      listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      authoritySelector: { kind: 'wallet' },
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlan(),
      keyHandle,
      participantIds: [1, 3],
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      providerIdentity: {
        kind: 'explicit_provider_user',
        provider: 'google',
        providerUserId: 'google:subject',
      },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(ecdsaProvisionCalls[0]).toMatchObject({
      runtimePolicy: {
        kind: 'scoped_policy',
        scope: manifest.durableMaterial.runtimePolicyScope,
      },
    });
  });

  test('persists sealed Email OTP signing-session refresh only for session-retained ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'loginWithEmailOtpWallet') {
          return emailOtpEcdsaUnlockWorkerResult(call);
        }
        if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-email-otp-session-secret',
            keyVersion: 'signing-session-seal-kek-test-r1',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
          };
        }
        return { ok: true };
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      authoritySelector: { kind: 'wallet' },
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlan(),
      keyHandle,
      participantIds: [1, 3],
      runtimePolicyScope,
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      providerIdentity: {
        kind: 'explicit_provider_user',
        provider: 'google',
        providerUserId: 'google:subject',
      },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    const sealCall = workerCalls.find(
      (call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial',
    );
    const sealedThresholdSessionId = sealCall?.request?.payload?.target?.thresholdSessionId;
    expect(sealedThresholdSessionId).toMatch(/^threshold-ecdsa-login-/);
    expect(sealCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'sealEmailOtpWarmSessionMaterial',
        payload: {
          target: {
            kind: 'ecdsa',
            thresholdSessionId: sealedThresholdSessionId,
          },
          transport: {
            relayerUrl: 'https://relay.example',
            walletSessionToken: expect.any(String),
            groupId: 'rfc2409-group2',
          },
        },
      },
    });
    expect(sealedRecordWrites).toHaveLength(2);
    expect(
      sealedRecordWrites.map((record) => record.ecdsaRestore?.chainTarget?.kind).sort(),
    ).toEqual(['evm', 'tempo']);
    for (const sealedRecordWrite of sealedRecordWrites) {
      expect(sealedRecordWrite).toMatchObject({
        sealedSecretB64u: 'sealed-email-otp-session-secret',
        curve: 'ecdsa',
        authMethod: 'email_otp',
        thresholdSessionIds: { ecdsa: sealedThresholdSessionId },
        walletId: 'alice.testnet',
        relayerUrl: 'https://relay.example',
        keyVersion: 'signing-session-seal-kek-test-r1',
        groupId: 'rfc2409-group2',
        remainingUses: 9,
      });
    }
  });

  test('fails session-retained Email OTP login when sealed refresh is not durably readable', async () => {
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      readExactSealedSession: async () => null,
    });

    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await expect(
      coordinator.loginWithEcdsaCapabilityInternal({
        walletSession: TEST_WALLET_SESSION,
        authoritySelector: { kind: 'wallet' },
        chainTarget: TEMPO_CHAIN_TARGET,
        challengeId: 'challenge-1',
        otpCode: '123456',
        emailHashHex: 'email-hash',
        routePlan: loginRoutePlan(),
        keyHandle,
        participantIds: [1, 3],
        runtimePolicyScope,
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        providerIdentity: {
          kind: 'explicit_provider_user',
          provider: 'google',
          providerUserId: 'google:subject',
        },
        ed25519YaoRecovery: { kind: 'not_requested' },
      }),
    ).rejects.toThrow(
      /^Email OTP sealed refresh (?:tempo:42431|evm:5042002) record was not durably persisted$/,
    );
  });

  test('persists sealed Email OTP refresh records for wallet-unlock ECDSA login under per-operation policy', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
    });
    const runtimePolicyScope = {
      orgId: 'org',
      projectId: 'proj',
      envId: 'dev',
      signingRootVersion: 'v1',
    };
    const keyHandle = await roleLocalEcdsaKeyHandle({
      walletId: 'alice.testnet',
      rpId: 'localhost',
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      authoritySelector: { kind: 'wallet' },
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      emailHashHex: 'email-hash',
      routePlan: loginRoutePlan(),
      keyHandle,
      participantIds: [1, 3],
      runtimePolicyScope,
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      providerIdentity: {
        kind: 'explicit_provider_user',
        provider: 'google',
        providerUserId: 'google:subject',
      },
      ed25519YaoRecovery: { kind: 'not_requested' },
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(true);
    expect(sealedRecordWrites.length).toBeGreaterThan(0);
  });

  test('explicit signing restore rehydrates session-retained ECDSA Email OTP material from sealed refresh record', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const manifest = (await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp')).manifest;
    const tempoChainTarget = manifest.signer.scope.targetMemberships[0];
    const sealedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      expiresAtMs,
      thresholdSessionId: 'ecdsa-session',
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      readActiveWalletSessionAuthorization: async () => ({
        kind: 'found',
        projection: activeEvmFamilyWalletSessionAuthorizationFixture({
          walletId: toWalletId(sealedRecord.walletId),
          authority: manifest.signer.authority,
          authMethod: 'email_otp',
        }).projection,
      }),
      listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
      resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }) => {
        const resolution = resolveExactEcdsaSealedRuntime({
          manifest,
          walletId,
          chainTarget,
          sealedRecords: [sealedRecord],
        });
        return resolution.kind === 'resolved'
          ? { kind: 'resolved', manifest, runtime: resolution.runtime }
          : resolution;
      },
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            emailOtpSessionHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
          };
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === sealedRecord.walletId &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget &&
        thresholdEcdsaChainTargetsEqual(filter.chainTarget, tempoChainTarget)
          ? [sealedRecord]
          : [],
      readExactSealedSession: async (thresholdSessionId, purpose) =>
        thresholdSessionId === 'ecdsa-session' &&
        purpose?.authMethod === 'email_otp' &&
        purpose?.curve === 'ecdsa' &&
        purpose?.chainTarget &&
        thresholdEcdsaChainTargetsEqual(purpose.chainTarget, tempoChainTarget)
          ? sealedRecord
          : null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const result = await coordinator.restorePersistedSessionForSigning(
      ecdsaRestoreInput({
        chainTarget: tempoChainTarget,
        materialActivation: sealedRecord.ecdsaRestore.roleLocalMaterialRef.materialActivation,
        manifest,
        walletId: sealedRecord.walletId,
        providerSubjectId: sealedRecord.ecdsaRestore.providerSubjectId,
      }),
    );

    expect(result).toMatchObject({
      attempted: 1,
      restored: 1,
      deferred: 0,
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );
    expect(restoreCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        payload: {
          sealedSecretB64u: sealedRecord.sealedSecretB64u,
          remainingUses: sealedRecord.remainingUses,
          expiresAtMs,
          transport: {
            relayerUrl: sealedRecord.relayerUrl,
            walletSessionToken: expect.any(String),
            signingSessionSealKeyVersion: TEST_SIGNING_SESSION_SEAL_KEY_VERSION,
            groupId: 'rfc2409-group2',
          },
          restore: {
            thresholdSessionId: 'ecdsa-session',
            walletId: sealedRecord.walletId,
            chainTarget: tempoChainTarget,
            keyHandle: sealedRecord.ecdsaRestore.keyHandle,
          },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: sealedRecord.walletId,
      source: 'email_otp',
      emailOtpAuthContext: emailOtpAuthContextFixture({
        walletId: sealedRecord.walletId,
        providerUserId: sealedRecord.ecdsaRestore.providerSubjectId,
      }),
    });
  });

  test('status reads do not probe sealed ECDSA records while session records are indexing', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({ expiresAtMs });
    const warnCalls: any[][] = [];
    const debugCalls: any[][] = [];
    const originalWarn = console.warn;
    const originalDebug = console.debug;
    console.warn = (...args: any[]) => {
      warnCalls.push(args);
    };
    console.debug = (...args: any[]) => {
      debugCalls.push(args);
    };
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
    });

    try {
      await coordinator.readWarmSessionStatusOnly({
        kind: 'ecdsa',
        thresholdSessionId: 'ecdsa-session',
      });
      await coordinator.readWarmSessionStatusOnly({
        kind: 'ecdsa',
        thresholdSessionId: 'ecdsa-session',
      });
    } finally {
      console.warn = originalWarn;
      console.debug = originalDebug;
    }

    expect(
      warnCalls.some((args) =>
        String(args[0] || '').includes(
          'sealed refresh restore missing session-retained ECDSA record',
        ),
      ),
    ).toBe(false);
    expect(
      debugCalls.filter((args) =>
        String(args[0] || '').includes('sealed refresh restore waiting for ECDSA record'),
      ),
    ).toHaveLength(0);
  });

  test('explicit signing restore restores sealed ECDSA Email OTP session from durable metadata', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const manifest = (await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp')).manifest;
    const tempoChainTarget = manifest.signer.scope.targetMemberships[0];
    const sealedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      expiresAtMs,
      thresholdSessionId: 'ecdsa-session',
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      readActiveWalletSessionAuthorization: async () => ({
        kind: 'found',
        projection: activeEvmFamilyWalletSessionAuthorizationFixture({
          walletId: toWalletId(sealedRecord.walletId),
          authority: manifest.signer.authority,
          authMethod: 'email_otp',
        }).projection,
      }),
      listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
      resolveCurrentEcdsaCapabilityRuntime: async ({ walletId, chainTarget }) => {
        const resolution = resolveExactEcdsaSealedRuntime({
          manifest,
          walletId,
          chainTarget,
          sealedRecords: [sealedRecord],
        });
        return resolution.kind === 'resolved'
          ? { kind: 'resolved', manifest, runtime: resolution.runtime }
          : resolution;
      },
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            emailOtpSessionHandle: emailOtpEcdsaClientRootHandleFromWorkerCall(call),
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === sealedRecord.walletId &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget &&
        thresholdEcdsaChainTargetsEqual(filter.chainTarget, tempoChainTarget)
          ? [sealedRecord]
          : [],
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const restoreResult = await coordinator.restorePersistedSessionForSigning(
      ecdsaRestoreInput({
        chainTarget: tempoChainTarget,
        materialActivation: sealedRecord.ecdsaRestore.roleLocalMaterialRef.materialActivation,
        manifest,
        walletId: sealedRecord.walletId,
        providerSubjectId: sealedRecord.ecdsaRestore.providerSubjectId,
      }),
    );
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreResult).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCall).toMatchObject({
      request: {
        payload: {
          transport: {
            walletSessionToken: expect.any(String),
          },
          restore: {
            thresholdSessionId: 'ecdsa-session',
            chainTarget: tempoChainTarget,
          },
        },
      },
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
  });

  test('wallet-scoped discovery enumerates durable sealed ECDSA records after reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const evmChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'evm',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const listFilters: unknown[] = [];
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: {
            mode: 'sealed_refresh_v1',
            protocol: { algorithm: 'shamir3pass-v2', groupId: 'rfc2409-group2' },
          },
        },
      },
      listExactSealedSessionsForWallet: async (args) => {
        listFilters.push(args.filter);
        expect(args).toMatchObject({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp' },
        });
        return args.filter?.curve === 'ecdsa' &&
          thresholdEcdsaChainTargetsEqual(args.filter.chainTarget, tempoChainTarget)
          ? [sealedRecord]
          : [];
      },
    });

    const first = await coordinator.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    const second = await coordinator.discoverPersistedSessionsForWallet({
      kind: 'discover_wallet_ecdsa_signing_sessions',
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });

    expect(first).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(second).toMatchObject({ listed: 1, discovered: 1, truncated: 0 });
    expect(listFilters).toHaveLength(4);
    expect(ecdsaCommitCalls).toHaveLength(0);
    expect(
      workerCalls.filter(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toHaveLength(0);
  });
});
