import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  WarmSessionMaterialClaimer,
  VolatileWarmSessionMaterialClearer,
  WarmSessionSealPersister,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaActivationChain,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ThresholdEcdsaActivationRequest } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { WarmSessionSealAndPersistPayload } from '@/core/types/secure-confirm-worker';
import {
  parseEcdsaThresholdKeyId,
  parseSigningSessionSealKeyVersion,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  toExactEcdsaSigningLaneIdentity,
  thresholdEcdsaSessionRecordReadModel,
  thresholdEcdsaRecordRpId,
  type ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  type ConsumeSingleUseEmailOtpEcdsaLaneResult,
  type ThresholdEcdsaSessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import { createClearVolatileWarmSessionMaterialCommand } from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '@/core/signingEngine/session/warmCapabilities/volatileWarmSessionId';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionProvisionPlan,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
  buildPasskeyEcdsaProvisionSecretSource,
  type EcdsaSessionProvisionPlan,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  ensureWarmEcdsaCapabilityReady,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  tryReuseReadyWarmEcdsaBootstrap,
} from '@/core/signingEngine/useCases/provisionEcdsaSession';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildEvmFamilyEcdsaSessionLanePolicy,
  resolveThresholdEcdsaKeyIdFromRecord,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { provisionWarmEd25519Capability } from '@/core/signingEngine/session/passkey/ed25519Provisioner';
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '@/core/signingEngine/session/operationState/warmSessionPolicyAdapter';
import { createWarmSessionStatusReader as createCoreWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type { ResolveExactEcdsaRecordResult } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/passkey/prfClaim';
import { ensureEcdsaPrfSealPersisted } from '@/core/signingEngine/session/passkey/runtime';
import type {
  EnsureWarmEcdsaCapabilityReadyResult,
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { SensitiveOperationPolicy } from '@shared/utils';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';

function testEcdsaChainId(chain: ThresholdEcdsaActivationChain): number {
  return chain === 'tempo' ? 42431 : 11155111;
}

const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SHARE32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function hexAddressToBase64Url(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function fixtureRouterAbEcdsaHssNormalSigning(args: {
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  sessionId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
}): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_key_id: args.walletKeyId,
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: args.signingRootId,
      signing_root_version: args.signingRootVersion,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_SHARE32_B64U,
        client_public_key33_b64u: args.clientVerifyingShareB64u,
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        ethereum_address20_b64u: hexAddressToBase64Url(args.ethereumAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: args.sessionId,
    },
  };
}

function fixtureRuntimePolicyScopeFromSigningRoot(
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

export function testEcdsaChainTarget(
  chain: ThresholdEcdsaActivationChain,
): ThresholdEcdsaChainTarget {
  return thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId: testEcdsaChainId(chain),
  });
}

function requirePasskeyCredentialIdForFixture(record: ThresholdEcdsaSessionRecord): string {
  const authMethod = record.ecdsaRoleLocalReadyRecord.authMethod;
  switch (authMethod.kind) {
    case 'passkey':
      return authMethod.credentialIdB64u;
    case 'email_otp':
      throw new Error('test passkey reconnect fixture requires passkey ECDSA auth material');
    default:
      return assertNever(authMethod);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected fixture branch: ${String(value)}`);
}
import type { WarmSessionTransitionEvent } from '@/core/signingEngine/session/warmCapabilities/transitions';

type SessionStorageMock = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
  clear: () => void;
};

export type WarmClaimFixture =
  | {
      state: 'warm';
      remainingUses: number;
      expiresAtMs: number;
      prfFirstB64u?: string;
    }
  | {
      state: 'missing' | 'expired' | 'exhausted' | 'unavailable';
      message?: string;
      code?: string;
    };

function isWarmClaimFixture(
  claim: WarmClaimFixture,
): claim is Extract<WarmClaimFixture, { state: 'warm' }> {
  return claim.state === 'warm';
}

export function ensureWarmSessionTestStorage(): SessionStorageMock {
  const globalObj = globalThis as { sessionStorage?: SessionStorageMock };
  if (globalObj.sessionStorage) return globalObj.sessionStorage;

  const store = new Map<string, string>();
  const sessionStorage: SessionStorageMock = {
    getItem: (key) => (store.has(key) ? String(store.get(key)) : null),
    setItem: (key, value) => {
      store.set(String(key), String(value));
    },
    removeItem: (key) => {
      store.delete(String(key));
    },
    clear: () => {
      store.clear();
    },
  };
  globalObj.sessionStorage = sessionStorage;
  return sessionStorage;
}

export function createThresholdEcdsaStoreFixture(): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
}

function exactEcdsaRecordOrNull(
  result: ResolveExactEcdsaRecordResult,
): ThresholdEcdsaSessionRecord | null {
  switch (result.kind) {
    case 'found':
      return result.record;
    case 'not_found':
      return null;
    case 'duplicate_records':
      throw new Error('duplicate exact ECDSA records in test fixture');
  }
  result satisfies never;
  throw new Error('unsupported exact ECDSA record result in test fixture');
}

function resolveFixtureExactEcdsaRecord(args: {
  statusReader: ReturnType<typeof createCoreWarmSessionStatusReader>;
  record: ThresholdEcdsaSessionRecord | null | undefined;
  source?: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord | null {
  if (!args.record) return null;
  return (
    exactEcdsaRecordOrNull(
      args.statusReader.resolveExactEcdsaRecord({
        lane: toExactEcdsaSigningLaneIdentity(args.record),
        ...(args.source ? { source: args.source } : {}),
      }),
    ) || args.record
  );
}

function chooseFixtureEcdsaRecordCandidate(args: {
  primary: ThresholdEcdsaSessionRecord | null | undefined;
  secondary: ThresholdEcdsaSessionRecord | null | undefined;
  thresholdSessionId: string;
}): ThresholdEcdsaSessionRecord | null {
  const candidates = [args.primary, args.secondary].filter(
    (record): record is ThresholdEcdsaSessionRecord => Boolean(record),
  );
  if (!args.thresholdSessionId) return candidates[0] || null;
  return (
    candidates.find(
      (record) => String(record.thresholdSessionId || '').trim() === args.thresholdSessionId,
    ) || null
  );
}

function requireFixtureEcdsaRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
  message: string,
): ThresholdEcdsaSessionRecord {
  if (record) return record;
  throw new Error(message);
}

export function resetWarmSessionFixtureState(deps: ThresholdEcdsaSessionStoreDeps): void {
  ensureWarmSessionTestStorage().clear();
  clearAllStoredThresholdEd25519SessionRecords();
  clearAllThresholdEcdsaSessionRecords(deps);
}

export function seedEd25519WarmSessionRecord(
  args: Partial<ThresholdEd25519SessionRecord> & {
    nearAccountId: string;
    thresholdSessionId: string;
    runtimeValidated?: boolean;
  },
): ThresholdEd25519SessionRecord {
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (args.source === 'email_otp'
      ? ({
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        } satisfies ThresholdEcdsaEmailOtpAuthContext)
      : undefined);
  const runtimePolicyScope =
    args.runtimePolicyScope || fixtureRuntimePolicyScopeFromSigningRoot('sr-test:dev', 'default');
  const signingGrantId = args.signingGrantId || `wsess-${String(args.thresholdSessionId).trim()}`;
  const relayerKeyId = args.relayerKeyId || 'rk-ed25519';
  const participantIds = args.participantIds || [1, 2];
  const walletId = String(args.walletId || args.nearAccountId);
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || args.nearAccountId);
  const walletSessionJwt =
    args.walletSessionJwt === ''
      ? ''
      : toFixtureEd25519WalletSessionJwt(args.walletSessionJwt || '', {
          walletId,
          nearAccountId: args.nearAccountId,
          nearEd25519SigningKeyId,
          sessionId: args.thresholdSessionId,
          signingGrantId,
          relayerKeyId,
          participantIds,
          runtimePolicyScope,
        });
  const record = upsertStoredThresholdEd25519SessionRecord({
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    rpId: args.rpId || 'wallet.example.test',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    relayerKeyId,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(args.clientVerifyingShareB64u !== ''
      ? { clientVerifyingShareB64u: args.clientVerifyingShareB64u || 'fixture-client-verifier' }
      : {}),
    ...(args.ed25519WorkerMaterialHandle !== ''
      ? {
          ed25519WorkerMaterialHandle:
            args.ed25519WorkerMaterialHandle ||
            `ed25519-worker-material:${args.thresholdSessionId}:fixture-binding`,
        }
      : {}),
    ...(args.ed25519WorkerMaterialBindingDigest !== ''
      ? {
          ed25519WorkerMaterialBindingDigest:
            args.ed25519WorkerMaterialBindingDigest || 'fixture-binding',
        }
      : {}),
    ...(args.signerSlot !== 0 ? { signerSlot: args.signerSlot || 1 } : {}),
    ...(args.keyVersion !== '' ? { keyVersion: args.keyVersion || 'threshold-ed25519-hss-v1' } : {}),
    routerAbNormalSigning: args.routerAbNormalSigning || {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-warm-session-fixture',
    },
    thresholdSessionKind: args.thresholdSessionKind || 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId,
    ...(args.source === 'email_otp'
      ? {}
      : {
          passkeyCredentialIdB64u:
            args.passkeyCredentialIdB64u || `passkey-credential-${args.thresholdSessionId}`,
        }),
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    expiresAtMs: args.expiresAtMs ?? Date.now() + 120_000,
    remainingUses: args.remainingUses ?? 7,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs: args.updatedAtMs ?? Date.now(),
    source: args.source || 'login',
  });
  if (!record) {
    throw new Error(`Failed to seed Ed25519 warm-session record for ${args.nearAccountId}`);
  }
  if (args.runtimeValidated) {
    markRouterAbEd25519WorkerMaterialRuntimeValidated(record);
  }
  return record;
}

function toFixtureEd25519WalletSessionJwt(
  token: string,
  args: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    sessionId: string;
    signingGrantId: string;
    relayerKeyId: string;
    participantIds: number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  },
): string {
  if (token.split('.').length === 3) return token;
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: args.walletId,
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      thresholdSessionId: args.sessionId,
      signingGrantId: args.signingGrantId,
      subjectId: args.walletId,
      relayerKeyId: args.relayerKeyId,
      rpId: 'wallet.example.test',
      thresholdExpiresAtMs: Date.now() + 120_000,
      participantIds: args.participantIds,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

export function createThresholdEcdsaBootstrapFixture(args: {
  nearAccountId: string;
  chain: ThresholdEcdsaActivationChain;
  rpId?: string;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  walletSessionJwt?: string;
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  relayerKeyId?: string;
  clientVerifyingShareB64u?: string;
  passkeyCredentialIdB64u?: string;
  participantIds?: number[];
  ethereumAddress?: string;
  signingGrantId?: string;
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
  const keyHandle = String(args.keyHandle || `ehss-key-${ecdsaThresholdKeyId}`).trim();
  const sessionId = String(args.sessionId || `sess-${chainLabel}-1`).trim();
  const sessionKind = args.sessionKind || 'jwt';
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
  const signingGrantId = String(args.signingGrantId || `wsess-${sessionId}`).trim();
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || 'default').trim();
  const walletKeyId = `wallet-key-${args.nearAccountId}`;
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    fixtureRuntimePolicyScopeFromSigningRoot(signingRootId, signingRootVersion);
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
    chain: args.chain,
    chainId: testEcdsaChainId(args.chain),
  });
  const roleLocalAuthMethod =
    args.roleLocalAuthMethod === 'email_otp'
      ? buildEcdsaRoleLocalEmailOtpAuthMethod({
          authSubjectId: args.emailOtpAuthSubjectId || `google:${args.nearAccountId}`,
        })
      : buildEcdsaRoleLocalPasskeyAuthMethod({
          credentialIdB64u: passkeyCredentialIdB64u,
          rpId,
        });
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_ECDSA_SHARE32_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId(args.nearAccountId),
      walletKeyId,
      rpId,
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
      hssClientSharePublicKey33B64u: clientVerifyingShareB64u,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress,
    }),
    authMethod: roleLocalAuthMethod,
  });
  const walletSessionJwt =
    sessionKind === 'jwt'
      ? toFixtureWalletSessionJwt(String(args.walletSessionJwt || `jwt:${sessionId}`).trim(), {
          nearAccountId: args.nearAccountId,
          sessionId,
          signingGrantId,
          relayerKeyId,
          ecdsaThresholdKeyId,
          participantIds,
          chainTarget,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        })
      : '';

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
      chainTarget,
      relayerUrl,
      keyHandle,
      ecdsaThresholdKeyId,
      participantIds: [...participantIds],
      backendBinding: {
        materialKind: 'role_local_ready_state_blob',
        relayerKeyId,
        clientVerifyingShareB64u,
        stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
        ecdsaRoleLocalReadyRecord,
      },
      thresholdSessionKind: sessionKind,
      thresholdSessionId: sessionId,
      signingGrantId,
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
      routerAbEcdsaHssNormalSigning: fixtureRouterAbEcdsaHssNormalSigning({
        walletId: args.nearAccountId,
        walletKeyId,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        sessionId,
        clientVerifyingShareB64u,
        thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        ethereumAddress,
      }),
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
    },
    passkeyCredentialIdB64u,
	    keygen: {
	      ok: true,
	      walletKeyId,
	      ecdsaThresholdKeyId,
      clientVerifyingShareB64u,
      relayerKeyId,
      participantIds: [...participantIds],
      chainId: testEcdsaChainId(args.chain),
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
    },
    session: {
      ok: true,
      thresholdSessionId: sessionId,
      signingGrantId,
      expiresAtMs: args.expiresAtMs ?? Date.now() + 120_000,
      remainingUses: args.remainingUses ?? 5,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(walletSessionJwt ? { jwt: walletSessionJwt } : {}),
      clientVerifyingShareB64u,
    },
  };
}

function toFixtureWalletSessionJwt(
  token: string,
  args: {
    nearAccountId: string;
    sessionId: string;
    signingGrantId: string;
    relayerKeyId: string;
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    chainTarget: ThresholdEcdsaChainTarget;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  },
): string {
  if (token.split('.').length === 3) return token;
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: args.nearAccountId,
      walletId: args.nearAccountId,
      kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
      thresholdSessionId: args.sessionId,
      signingGrantId: args.signingGrantId,
      subjectId: args.nearAccountId,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      relayerKeyId: args.relayerKeyId,
      rpId: 'localhost',
      thresholdExpiresAtMs: Date.now() + 120_000,
      participantIds: args.participantIds,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

export function seedEcdsaWarmSessionRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: string;
    chain: ThresholdEcdsaActivationChain;
    source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    bootstrap?: ThresholdEcdsaSessionBootstrapResult;
    signingSessionSeal?: {
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
    runtimeValidated?: boolean;
  },
) {
  const source = args.source || 'login';
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (source === 'email_otp'
      ? ({
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
          authSubjectId: args.nearAccountId,
        } satisfies ThresholdEcdsaEmailOtpAuthContext)
      : undefined);
  const normalizedEmailOtpAuthContext =
    source === 'email_otp' && emailOtpAuthContext
      ? {
          ...emailOtpAuthContext,
          authSubjectId: emailOtpAuthContext.authSubjectId || args.nearAccountId,
        }
      : emailOtpAuthContext;
  const bootstrap =
    args.bootstrap ||
    (source === 'email_otp'
      ? createThresholdEcdsaBootstrapFixture({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          roleLocalAuthMethod: 'email_otp',
          emailOtpAuthSubjectId: normalizedEmailOtpAuthContext?.authSubjectId || args.nearAccountId,
        })
      : createThresholdEcdsaBootstrapFixture({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
        }));
  const baseArgs = {
    walletId: args.nearAccountId,
    chainTarget: bootstrap.thresholdEcdsaKeyRef.chainTarget || testEcdsaChainTarget(args.chain),
    bootstrap,
    ...(args.signingSessionSeal
      ? {
          signingSessionSeal: {
            ...(args.signingSessionSeal.keyVersion
              ? {
                  signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
                    args.signingSessionSeal.keyVersion,
                  ),
                }
              : {}),
            ...(args.signingSessionSeal.shamirPrimeB64u
              ? { shamirPrimeB64u: args.signingSessionSeal.shamirPrimeB64u }
              : {}),
          },
        }
      : {}),
  };
  const record = source === 'email_otp'
    ? upsertThresholdEcdsaSessionFromBootstrap(deps, {
        ...baseArgs,
        source: 'email_otp',
        emailOtpAuthContext:
          normalizedEmailOtpAuthContext ||
          ({
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
            authSubjectId: args.nearAccountId,
          } satisfies ThresholdEcdsaEmailOtpAuthContext),
      })
    : upsertThresholdEcdsaSessionFromBootstrap(deps, {
        ...baseArgs,
        source,
      });
  if (args.runtimeValidated) {
    markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record);
  }
  return record;
}

export function createWarmSessionStatusReader(
  claimsBySessionId: Record<string, WarmClaimFixture>,
): Pick<
  WarmSessionStatusReader & WarmSessionStatusBatchReader,
  'getWarmSessionStatus' | 'getWarmSessionStatuses'
> {
  const getWarmSessionStatus: WarmSessionStatusReader['getWarmSessionStatus'] = async ({
    sessionId,
  }) => {
    const claim = claimsBySessionId[String(sessionId || '').trim()];
    if (!claim || claim.state === 'missing') {
      return {
        ok: false as const,
        code: 'not_found',
        message: claim?.message || 'missing',
      };
    }
    if (claim.state === 'unavailable') {
      return {
        ok: false as const,
        code: claim.code || 'worker_error',
        message: claim.message || 'unavailable',
      };
    }
    if (claim.state === 'expired' || claim.state === 'exhausted') {
      return {
        ok: false as const,
        code: claim.state,
        message: claim.message || claim.state,
      };
    }
    if (!isWarmClaimFixture(claim)) {
      return {
        ok: false as const,
        code: 'not_found',
        message: claim.message || 'missing',
      };
    }
    return {
      ok: true as const,
      remainingUses: claim.remainingUses,
      expiresAtMs: claim.expiresAtMs,
    };
  };
  return {
    getWarmSessionStatus,
    getWarmSessionStatuses: async ({ sessionIds }) => ({
      results: await Promise.all(
        (Array.isArray(sessionIds) ? sessionIds : []).map(async (sessionId) => ({
          sessionId: String(sessionId || '').trim(),
          result: await getWarmSessionStatus({ sessionId: String(sessionId || '').trim() }),
        })),
      ),
    }),
  };
}

export function createWarmSessionUiConfirmFixture(args: {
  claimsBySessionId: Record<string, WarmClaimFixture>;
  sealAndPersistResultBySessionId?: Record<
    string,
    | {
        ok: true;
        sealedSecretB64u: string;
        keyVersion?: string;
        remainingUses: number;
        expiresAtMs: number;
      }
    | {
        ok: false;
        code: string;
        message: string;
      }
  >;
}) {
  const sealCalls: WarmSessionSealAndPersistPayload[] = [];
  const readStatus = createWarmSessionStatusReader(args.claimsBySessionId).getWarmSessionStatus;

  const touchConfirm: Pick<
    WarmSessionStatusReader & WarmSessionMaterialClaimer & WarmSessionSealPersister,
    'getWarmSessionStatus' | 'claimWarmSessionMaterial' | 'sealAndPersistWarmSessionMaterial'
  > = {
    getWarmSessionStatus: readStatus,
    claimWarmSessionMaterial: async ({ sessionId, uses }) => {
      const normalizedSessionId = String(sessionId || '').trim();
      const claim = args.claimsBySessionId[normalizedSessionId];
      if (!claim || claim.state === 'missing') {
        return {
          ok: false as const,
          code: 'not_found',
          message: claim?.message || 'missing',
        };
      }
      if (claim.state === 'unavailable') {
        return {
          ok: false as const,
          code: claim.code || 'worker_error',
          message: claim.message || 'unavailable',
        };
      }
      if (claim.state === 'expired' || claim.state === 'exhausted') {
        return {
          ok: false as const,
          code: claim.state,
          message: claim.message || claim.state,
        };
      }

      if (!isWarmClaimFixture(claim)) {
        return {
          ok: false as const,
          code: 'not_found',
          message: claim.message || 'missing',
        };
      }

      const warmClaim = claim;
      const consumeUses = Math.max(1, Math.floor(Number(uses) || 1));
      if (warmClaim.remainingUses < consumeUses) {
        args.claimsBySessionId[normalizedSessionId] = { state: 'exhausted' };
        return {
          ok: false as const,
          code: 'exhausted',
          message: 'exhausted',
        };
      }

      warmClaim.remainingUses -= consumeUses;
      const remainingUses = warmClaim.remainingUses;
      const prfFirstB64u = String(
        warmClaim.prfFirstB64u || `prf-first:${normalizedSessionId}:${remainingUses}`,
      ).trim();
      if (remainingUses <= 0) {
        args.claimsBySessionId[normalizedSessionId] = { state: 'exhausted' };
      }
      return {
        ok: true as const,
        prfFirstB64u,
        remainingUses,
        expiresAtMs: claim.expiresAtMs,
      };
    },
    sealAndPersistWarmSessionMaterial: async (payload) => {
      sealCalls.push(payload);
      return (
        args.sealAndPersistResultBySessionId?.[String(payload.sessionId || '').trim()] || {
          ok: false as const,
          code: 'not_enabled',
          message: 'not enabled',
        }
      );
    },
  };

  return {
    claimsBySessionId: args.claimsBySessionId,
    sealCalls,
    touchConfirm,
  };
}

type WarmSessionTestServicesDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialClaimer &
        WarmSessionSealPersister &
        VolatileWarmSessionMaterialClearer,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'claimWarmSessionMaterial'
      | 'sealAndPersistWarmSessionMaterial'
      | 'clearVolatileWarmSessionMaterial'
    >
  >;
  clearThresholdEcdsaSessionRecordForWalletTarget?: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
  clearThresholdEcdsaSigningArtifactsForLane?: (args: {
    record: ThresholdEcdsaSessionRecord;
  }) => void | Promise<void>;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listThresholdEcdsaRecordsForWalletTarget?: (args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Array<{ source: ThresholdEcdsaSessionStoreSource; record: ThresholdEcdsaSessionRecord }>;
  provisionThresholdEcdsaSession?: (
    args: EcdsaBootstrapRequest | ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

function resolveTestEcdsaBootstrapArgs(args: {
  request: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  };
  warmSession: Awaited<
    ReturnType<ReturnType<typeof createWarmSessionCapabilityReader>['getWarmSession']>
  >;
}): EcdsaBootstrapRequest {
  const chainTarget = testEcdsaChainTarget(args.request.chain);
  const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession: args.warmSession,
    chainTarget,
  });
  const reusableWarmCapability = primary.prfClaim?.state === 'warm' ? primary : null;
  const preferredMetadataCapability = primary.record
    ? primary
    : secondary.record
      ? secondary
      : null;
  const participantIds =
    normalizeParticipantIds(primary.record?.participantIds) ||
    normalizeParticipantIds(secondary.record?.participantIds);
  const ecdsaThresholdKeyId = (() => {
    const candidate = primary.record || secondary.record;
    if (!candidate) return undefined;
    try {
      return String(
        resolveThresholdEcdsaKeyIdFromRecord({
          record: candidate,
        }),
      ).trim();
    } catch {
      return undefined;
    }
  })();
  const targetBaseArgs = {
    walletId: args.request.nearAccountId,
    chainTarget,
    ...(args.request.source ? { source: args.request.source } : {}),
    ...(preferredMetadataCapability?.record?.relayerUrl
      ? { relayerUrl: preferredMetadataCapability.record.relayerUrl }
      : {}),
    ...(ecdsaThresholdKeyId && participantIds
      ? {
          keyIntent: {
            kind: 'existing_ecdsa_key' as const,
            ecdsaThresholdKeyId,
            participantIds,
          },
        }
      : {}),
  };
  const reuseBaseArgs = {
    walletId: targetBaseArgs.walletId,
    chainTarget: targetBaseArgs.chainTarget,
    kind: 'reuse_warm_ecdsa_bootstrap' as const,
    ...(targetBaseArgs.source ? { source: targetBaseArgs.source } : {}),
    ...(targetBaseArgs.relayerUrl ? { relayerUrl: targetBaseArgs.relayerUrl } : {}),
    ...(targetBaseArgs.keyIntent ? { keyIntent: targetBaseArgs.keyIntent } : {}),
  };

  const sessionId = toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId);
  const signingGrantId = toOptionalNonEmptyString(reusableWarmCapability?.record?.signingGrantId);
  const walletSessionJwt = toOptionalNonEmptyString(reusableWarmCapability?.auth?.walletSessionJwt);

  if (sessionId && signingGrantId && walletSessionJwt) {
    if (!reusableWarmCapability?.record) {
      throw new Error('test threshold-session reconnect requires a reusable ECDSA record');
    }
    const readModel = thresholdEcdsaSessionRecordReadModel(reusableWarmCapability.record);
    const passkeyCredentialIdB64u = requirePasskeyCredentialIdForFixture(
      reusableWarmCapability.record,
    );
    return {
      kind: 'wallet_session_reconnect_ecdsa_bootstrap',
      source: targetBaseArgs.source,
      relayerUrl: targetBaseArgs.relayerUrl,
      keyHandle: reusableWarmCapability.record.keyHandle,
      key: readModel.key,
      lanePolicy: buildEvmFamilyEcdsaSessionLanePolicy({
        chainTarget,
        thresholdSessionId: sessionId,
        signingGrantId,
        thresholdSessionKind: 'jwt',
        ttlMs: Math.max(1, readModel.lane.expiresAtMs - Date.now()),
        remainingUses: readModel.lane.remainingUses,
      }),
      routeAuth: {
        kind: 'wallet_session',
        jwt: walletSessionJwt,
      },
      passkeyPrfFirstB64u: 'reconnect-client-root-share',
      passkeyCredentialIdB64u,
    };
  }
  return reuseBaseArgs;
}

export function createWarmSessionTestServices(deps: WarmSessionTestServicesDeps = {}) {
  const reconnectInFlightByCapability = new Map<
    string,
    Promise<EnsureWarmEcdsaCapabilityReadyResult>
  >();
  const sealPersistInFlightBySessionId = new Map<string, Promise<void>>();
  const getEmailOtpWarmSessionStatus =
    deps.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof deps.touchConfirm?.getWarmSessionStatus === 'function') {
        return await deps.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
    });
  const statusReader = createCoreWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const clearEcdsaEphemeralMaterial = async (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId?: string;
  }): Promise<void> => {
    const thresholdSessionId = parseVolatileWarmSessionId(args.thresholdSessionId);
    if (typeof deps.clearThresholdEcdsaSigningArtifactsForLane === 'function') {
      await Promise.resolve(
        deps.clearThresholdEcdsaSigningArtifactsForLane({
          record: args.record,
        }),
      ).catch(() => undefined);
    }
    if (
      thresholdSessionId &&
      typeof deps.touchConfirm?.clearVolatileWarmSessionMaterial === 'function'
    ) {
      await deps.touchConfirm
        .clearVolatileWarmSessionMaterial(
          createClearVolatileWarmSessionMaterialCommand(thresholdSessionId),
        )
        .catch(() => undefined);
    }
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm ?? null,
    signingSessionSeal:
      deps.signingSessionSeal?.keyVersion && deps.signingSessionSeal.shamirPrimeB64u
        ? {
            signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
              deps.signingSessionSeal.keyVersion,
            ),
            shamirPrimeB64u: deps.signingSessionSeal.shamirPrimeB64u,
          }
        : null,
    getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const getWarmSession = (walletId: string | WalletId) =>
    capabilityReader.getWarmSession(toWalletId(walletId));
  const claimWarmSessionPrfFirstMaterial = (args: {
    thresholdSessionId: string;
    errorContext: string;
    uses?: number;
  }) =>
    claimWarmSessionPrfFirst({
      touchConfirm: deps.touchConfirm,
      thresholdSessionId: args.thresholdSessionId,
      errorContext: args.errorContext,
      uses: args.uses,
    });
  const provisionEcdsaCapability = async (args: EcdsaBootstrapRequest) => {
    const provisionThresholdEcdsaSession =
      deps.provisionThresholdEcdsaSession ||
      (async () => {
        throw new Error('provisionThresholdEcdsaSession test dependency is required');
      });
    return await provisionThresholdEcdsaSession(args);
  };

  return {
    getWarmSession,
    resolveEd25519RecordByThresholdSessionId:
      capabilityReader.resolveEd25519RecordByThresholdSessionId,
    resolveEcdsaRecordByThresholdSessionId: capabilityReader.resolveEcdsaRecordByThresholdSessionId,
    resolveEd25519AuthByThresholdSessionId: capabilityReader.resolveEd25519AuthByThresholdSessionId,
    resolveEcdsaAuthByThresholdSessionId: capabilityReader.resolveEcdsaAuthByThresholdSessionId,
    resolveEmailOtpSigningSessionAuthLane: capabilityReader.resolveEmailOtpSigningSessionAuthLane,
    getEd25519CapabilityByThresholdSessionId:
      capabilityReader.getEd25519CapabilityByThresholdSessionId,
    getEcdsaCapabilityByThresholdSessionId: capabilityReader.getEcdsaCapabilityByThresholdSessionId,
    getEcdsaCapabilityForLane: capabilityReader.getEcdsaCapabilityForLane,
    resolveEcdsaSealTransportByThresholdSessionId:
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
    provisionEd25519Capability: (args: ProvisionWarmEd25519CapabilityArgs) =>
      provisionWarmEd25519Capability(
        {
          getWarmSession,
          provisionThresholdEd25519Session: deps.provisionThresholdEd25519Session,
          onTransition: deps.onTransition,
        },
        args,
      ),
    resolveEcdsaBootstrapRequest: async (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      resolveTestEcdsaBootstrapArgs({
        request: args,
        warmSession: await getWarmSession(args.nearAccountId),
      }),
    provisionEcdsaCapability,
    tryReuseReadyEcdsaBootstrap: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      tryReuseReadyWarmEcdsaBootstrap(
        {
          getWarmSession,
          listThresholdEcdsaRecordsForWalletTarget:
            deps.listThresholdEcdsaRecordsForWalletTarget || (() => []),
        },
        {
          walletId: toWalletId(args.nearAccountId),
          ...(args.source ? { source: args.source } : {}),
          chainTarget: testEcdsaChainTarget(args.chain),
        },
      ),
    ensureEcdsaCapabilityReady: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
      usesNeeded?: number;
      requiredSignatureUses?: number;
      thresholdSessionId?: string;
      signingGrantId?: string;
      sessionBudgetUses?: number;
      passkeyPrfFirstB64u?: string;
      runtimeScopeBootstrap?: { environmentId: string; publishableKey: string };
      keyRef?: ThresholdEcdsaSecp256k1KeyRef;
      plan?: EcdsaSessionProvisionPlan;
    }) =>
      (async () => {
        const chainTarget = testEcdsaChainTarget(args.chain);
        const walletId = toWalletId(args.nearAccountId);
        const exactThresholdSessionId = String(args.thresholdSessionId || '');
        const warmSession = await getWarmSession(args.nearAccountId);
        const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
          warmSession,
          chainTarget,
        });
        const candidateRecord = resolveFixtureExactEcdsaRecord({
          statusReader,
          record: chooseFixtureEcdsaRecordCandidate({
            primary: primary.record,
            secondary: secondary.record,
            thresholdSessionId: exactThresholdSessionId,
          }),
          ...(args.source ? { source: args.source } : {}),
        });
        const record =
          candidateRecord ||
          (args.keyRef
            ? resolveFixtureExactEcdsaRecord({
                statusReader,
                record: chooseFixtureEcdsaRecordCandidate({
                  primary: primary.record,
                  secondary: secondary.record,
                  thresholdSessionId: String(args.keyRef.thresholdSessionId || ''),
                }),
                ...(args.source ? { source: args.source } : {}),
              })
            : null);
        if (!record) {
          throw new Error('test ECDSA provision requires session record material');
        }
        const resolvedPlan =
          args.plan ||
          (async () => {
            const identity = buildEcdsaSessionIdentity({
              thresholdSessionId: exactThresholdSessionId || record.thresholdSessionId,
              signingGrantId: String(args.signingGrantId || '') || record.signingGrantId,
            });
            const signingKeyContext = buildEcdsaSigningKeyContextFromRecord(record);
            const sessionBudgetUses = Number(args.sessionBudgetUses || 1);
            if (args.passkeyPrfFirstB64u) {
              return buildEcdsaSessionProvisionPlan({
                kind: 'passkey_ecdsa_session_provision',
                key: buildEvmFamilyEcdsaKeyIdentityFromRecord({
                  record,
                  walletKeyId: record.ecdsaRoleLocalReadyRecord.publicFacts.walletKeyId,
                }),
                chainTarget,
                sessionIdentity: identity,
                signingKeyContext,
                sessionBudgetUses,
                requestId: 'test-request-id',
                sessionKind: 'jwt',
                provisionSecretSource: buildPasskeyEcdsaProvisionSecretSource({
                  passkeyPrfFirstB64u: String(args.passkeyPrfFirstB64u || ''),
                  webauthnAuthentication: {
                    id: 'test-credential',
                    rawId: 'test-raw-id',
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                      clientDataJSON: 'test-client-data',
                      authenticatorData: 'test-authenticator-data',
                      signature: 'test-signature',
                      userHandle: undefined,
                    },
                    clientExtensionResults: {
                      prf: {
                        results: {
                          first: String(args.passkeyPrfFirstB64u || ''),
                          second: undefined,
                        },
                      },
                    },
                  },
                }),
                activationMaterial: { kind: 'session_record' },
                ...(record.runtimePolicyScope
                  ? { runtimePolicyScope: record.runtimePolicyScope }
                  : {}),
              });
            }
            return buildEcdsaSessionProvisionPlan({
              kind: 'ecdsa_session_reconnect',
              chainTarget,
              sessionIdentity: identity,
              sessionBudgetUses,
              reconnectMaterial: buildEcdsaReconnectMaterial({
                record,
              }),
            });
          })();

        const plan = await resolvedPlan;
        const readinessDeps = {
          getWarmSession,
          listThresholdEcdsaRecordsForWalletTarget:
            deps.listThresholdEcdsaRecordsForWalletTarget || (() => []),
          canProvisionEcdsaCapability: typeof deps.provisionThresholdEcdsaSession === 'function',
          provisionThresholdEcdsaSession:
            deps.provisionThresholdEcdsaSession ||
            (async () => {
              throw new Error('provisionThresholdEcdsaSession test dependency is required');
            }),
          touchConfirm: deps.touchConfirm || {},
          resolveExactEcdsaRecord: (
            recordArgs: Parameters<typeof statusReader.resolveExactEcdsaRecord>[0],
          ) => statusReader.resolveExactEcdsaRecord(recordArgs),
          readEcdsaCapabilityForLane: capabilityReader.getEcdsaCapabilityForLane,
          reconnectInFlightByCapability,
          onTransition: deps.onTransition,
        };
        const readinessArgsBase = {
          walletId,
          source: args.source || record.source,
          usesNeeded: args.usesNeeded ?? args.requiredSignatureUses,
          runtimeScopeBootstrap: args.runtimeScopeBootstrap,
          chainTarget,
          sessionBudgetUses: Number(args.sessionBudgetUses || 1),
        };
        switch (plan.kind) {
          case 'wallet_session_ecdsa_reconnect':
          case 'passkey_ecdsa_session_provision':
            return await ensureWarmEcdsaCapabilityReady(readinessDeps, {
              ...readinessArgsBase,
              record,
              plan,
            });
          case 'email_otp_ecdsa_session_provision':
            return await ensureWarmEcdsaCapabilityReady(readinessDeps, {
              ...readinessArgsBase,
              record,
              plan,
            });
        }
        plan satisfies never;
        throw new Error('unsupported test ECDSA provision plan');
      })(),
    assertEcdsaSigningSessionReady: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdSessionId: unknown;
      usesNeeded?: number;
    }) =>
      statusReader.assertEcdsaSigningSessionReady({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
        thresholdSessionId: args.thresholdSessionId,
        usesNeeded: args.usesNeeded,
      }),
    getEd25519SigningSessionStatus: statusReader.getEd25519SigningSessionStatus,
    getEd25519SigningSessionStatusForSession: statusReader.getEd25519SigningSessionStatusForSession,
    getEcdsaSigningSessionStatus: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdSessionId: string;
    }) =>
      statusReader.getEcdsaSigningSessionStatus({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
        thresholdSessionId: args.thresholdSessionId,
      }),
    listEcdsaSigningSessionStatuses: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
    }) =>
      statusReader.listEcdsaSigningSessionStatuses({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
      }),
    claimWarmSessionPrfFirstMaterial,
    ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
      chain?: ThresholdEcdsaActivationChain;
      thresholdSessionId: string;
      required?: boolean;
      errorContext?: string;
    }) =>
      ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        lane: toExactEcdsaSigningLaneIdentity(
          requireFixtureEcdsaRecord(
            resolveFixtureExactEcdsaRecord({
              statusReader,
              record: chooseFixtureEcdsaRecordCandidate({
                primary: capabilityReader.resolveEcdsaRecordByThresholdSessionId(
                  args.thresholdSessionId,
                ),
                secondary: null,
                thresholdSessionId: args.thresholdSessionId,
              }),
            }),
            'test ECDSA seal persistence requires exact session record',
          ),
        ),
        required: args.required,
        errorContext: args.errorContext,
        sealPersistInFlightBySessionId,
        resolveSealTransport: capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
      }),
    applyEcdsaPostSignPolicy: (args: {
      walletId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      source?: ThresholdEcdsaSessionStoreSource;
      selectedRecord: ThresholdEcdsaSessionRecord;
    }) =>
      applyWarmSessionEcdsaPostSignPolicy(
        {
          getWarmSession,
          resolveExactEcdsaRecord: (recordArgs) => statusReader.resolveExactEcdsaRecord(recordArgs),
          consumeSingleUseEmailOtpEcdsaLane: deps.consumeSingleUseEmailOtpEcdsaLane,
          clearEcdsaEphemeralMaterial,
        },
        {
          lane: toExactEcdsaSigningLaneIdentity(args.selectedRecord),
          selectedRecord: args.selectedRecord,
        },
      ),
    assertEcdsaOperationAllowed: (args: {
      walletId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      operationLabel: string;
      source?: ThresholdEcdsaSessionStoreSource;
      sensitivePolicy?: SensitiveOperationPolicy;
    }) =>
      assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession,
          resolveExactEcdsaRecord: (recordArgs) => statusReader.resolveExactEcdsaRecord(recordArgs),
        },
        {
          lane: toExactEcdsaSigningLaneIdentity(
            requireFixtureEcdsaRecord(
              capabilityReader.resolveEcdsaRecordByThresholdSessionId(args.thresholdSessionId || ''),
              'test ECDSA operation allowed requires exact session record',
            ),
          ),
          operationLabel: args.operationLabel,
          source: args.source || 'login',
          sensitivePolicy: args.sensitivePolicy,
        },
      ),
  };
}
