import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalWorkerHandle,
  parseSigningSessionSealKeyVersion,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  parseRawThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
  upsertThresholdEd25519SessionFact,
  upsertThresholdEcdsaSessionFromBootstrap,
} from '@/core/signingEngine/session/persistence/records';
import {
  bindLiveEcdsaRoleLocalMaterial,
  buildPersistedEcdsaRoleLocalMaterial,
} from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { parseEcdsaDerivationRoleLocalKeyRecord } from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { EcdsaDerivationRoleLocalKeyRecord } from '../../../packages/sdk-server-ts/src/core/types';
import {
  createThresholdEcdsaBootstrapFixture,
  fixtureRuntimePolicyScopeFromSigningRoot,
} from './ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './ecdsaChainTarget.fixtures';

const FIXTURE_EMAIL_HASH_HEX = '11'.repeat(32);

type SessionStorageMock = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
  clear: () => void;
};

type SeedEd25519WarmSessionRecordArgs = Partial<ThresholdEd25519SessionRecord> & {
  nearAccountId: string;
  thresholdSessionId: string;
};

function ensureWarmSessionTestStorage(): SessionStorageMock {
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

export function resetWarmSessionFixtureState(deps: ThresholdEcdsaSessionStoreDeps): void {
  ensureWarmSessionTestStorage().clear();
  clearAllStoredThresholdEd25519SessionRecords();
  clearAllThresholdEcdsaSessionRecords(deps);
}

export function seedEd25519WarmSessionRecord(
  args: SeedEd25519WarmSessionRecordArgs,
): ThresholdEd25519SessionRecord {
  const walletId = String(args.walletId || args.nearAccountId);
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || args.nearAccountId);
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (args.source === 'email_otp'
      ? buildEmailOtpAuthContextForWalletAuthMethod({
          policy: 'session',
          walletId,
          emailHashHex: FIXTURE_EMAIL_HASH_HEX,
          retention: 'session',
          reason: 'login',
          provider: 'email',
          providerUserId: walletId,
        })
      : undefined);
  const runtimePolicyScope =
    args.runtimePolicyScope || fixtureRuntimePolicyScopeFromSigningRoot('sr-test:dev', 'default');
  const signingGrantId = args.signingGrantId || `wsess-${String(args.thresholdSessionId).trim()}`;
  const relayerKeyId = args.relayerKeyId || 'rk-ed25519';
  const participantIds = args.participantIds || [1, 2];
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
  const record = upsertThresholdEd25519SessionFact({
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    rpId: args.rpId || 'wallet.example.test',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    relayerKeyId,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    // signerSlot is required by the upsert input; 0 normalizes to 0 in the
    // production upsert exactly as the previously-omitted property did.
    signerSlot: args.signerSlot === 0 ? 0 : args.signerSlot || 1,
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
  return record;
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
): ThresholdEcdsaSessionRecord {
  const source = args.source || 'login';
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (source === 'email_otp'
      ? buildEmailOtpAuthContextForWalletAuthMethod({
          policy: 'session',
          walletId: args.nearAccountId,
          emailHashHex: FIXTURE_EMAIL_HASH_HEX,
          retention: 'session',
          reason: 'login',
          provider: 'google',
          providerUserId: args.nearAccountId,
        })
      : undefined);
  const emailOtpProviderUserId =
    source === 'email_otp' && emailOtpAuthContext
      ? emailOtpAuthContextProviderUserId(emailOtpAuthContext)
      : '';
  const bootstrap =
    args.bootstrap ||
    (source === 'email_otp'
      ? createThresholdEcdsaBootstrapFixture({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          roleLocalAuthMethod: 'email_otp',
          emailOtpAuthSubjectId: emailOtpProviderUserId || args.nearAccountId,
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
  const record =
    source === 'email_otp'
      ? upsertThresholdEcdsaSessionFromBootstrap(deps, {
          ...baseArgs,
          purpose: 'transaction_signing',
          source: 'email_otp',
          emailOtpAuthContext: requireEmailOtpFixtureAuthContext(emailOtpAuthContext),
        })
      : upsertThresholdEcdsaSessionFromBootstrap(deps, {
          ...baseArgs,
          purpose: 'transaction_signing',
          source,
        });
  if (args.runtimeValidated) {
    markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record);
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

function requireEmailOtpFixtureAuthContext(
  context: ThresholdEcdsaEmailOtpAuthContext | undefined,
): ThresholdEcdsaEmailOtpAuthContext {
  if (context) return context;
  throw new Error('Email OTP ECDSA fixture requires normalized auth context');
}

type EcdsaSessionRecordFixtureSharedArgs = {
  walletId: string;
  /** Chain family for the bootstrap fixture; derived from `chainTarget.kind` when omitted. */
  chain?: ThresholdEcdsaActivationChain;
  /** Exact chain target stored on the record; must share the fixture chain family/chainId. */
  chainTarget?: ThresholdEcdsaChainTarget;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  thresholdSessionId?: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  relayerUrl?: string;
  relayerKeyId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootId?: string;
  signingRootVersion?: string;
  ethereumAddress?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
};

function ecdsaFixtureChainBinding(args: EcdsaSessionRecordFixtureSharedArgs): {
  chain: ThresholdEcdsaActivationChain;
  chainTarget: ThresholdEcdsaChainTarget;
} {
  const chain = args.chain || (args.chainTarget?.kind === 'tempo' ? 'tempo' : args.chainTarget ? 'evm' : 'tempo');
  const fixtureTarget = testEcdsaChainTarget(chain);
  const chainTarget = args.chainTarget || fixtureTarget;
  if (!thresholdEcdsaChainTargetsEqual(chainTarget, fixtureTarget)) {
    throw new Error(
      'ECDSA session record fixture chainTarget must match the fixture chain family/chainId',
    );
  }
  return { chain, chainTarget };
}

function ecdsaFixtureBootstrapArgs(
  args: EcdsaSessionRecordFixtureSharedArgs,
  chain: ThresholdEcdsaActivationChain,
) {
  const signingRoot = args.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope)
    : undefined;
  const signingRootId = args.signingRootId || signingRoot?.signingRootId;
  const signingRootVersion = args.signingRootVersion || signingRoot?.signingRootVersion;
  return {
    nearAccountId: args.walletId,
    chain,
    ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
    ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
    ...(args.thresholdSessionId ? { sessionId: args.thresholdSessionId } : {}),
    ...(args.signingGrantId ? { signingGrantId: args.signingGrantId } : {}),
    ...(args.walletSessionJwt ? { walletSessionJwt: args.walletSessionJwt } : {}),
    ...(args.relayerUrl ? { relayerUrl: args.relayerUrl } : {}),
    ...(args.relayerKeyId ? { relayerKeyId: args.relayerKeyId } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(args.ethereumAddress ? { ethereumAddress: args.ethereumAddress } : {}),
    ...(args.expiresAtMs !== undefined ? { expiresAtMs: args.expiresAtMs } : {}),
    ...(args.remainingUses !== undefined ? { remainingUses: args.remainingUses } : {}),
  };
}

function ecdsaFixtureReadyRecord(bootstrap: ThresholdEcdsaSessionBootstrapResult) {
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (binding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('ECDSA session record fixture requires a role-local ready-state bootstrap');
  }
  return binding.ecdsaRoleLocalReadyRecord;
}

function ecdsaSessionRecordRawFromBootstrapFixture(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  chainTarget: ThresholdEcdsaChainTarget;
  updatedAtMs?: number;
}): Record<string, unknown> {
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const binding = keyRef.backendBinding;
  if (binding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('ECDSA session record fixture requires a role-local ready-state bootstrap');
  }
  const readyRecord = binding.ecdsaRoleLocalReadyRecord;
  const participantIds = keyRef.participantIds;
  if (!participantIds) {
    throw new Error('ECDSA session record fixture requires bootstrap participantIds');
  }
  const sessionScope = (args.bootstrap.session as { runtimePolicyScope?: unknown })
    .runtimePolicyScope;
  return {
    purpose: 'transaction_signing',
    walletId: keyRef.userId,
    evmFamilySigningKeySlotId: args.bootstrap.keygen.evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    relayerUrl: keyRef.relayerUrl,
    keyHandle: keyRef.keyHandle,
    ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
    signingRootId: readyRecord.publicFacts.signingRootId,
    signingRootVersion: readyRecord.publicFacts.signingRootVersion,
    relayerKeyId: binding.relayerKeyId,
    clientVerifyingShareB64u: binding.clientVerifyingShareB64u,
    ecdsaRoleLocalAuthMethod: readyRecord.authMethod,
    ecdsaRoleLocalPublicFacts: readyRecord.publicFacts,
    participantIds: [...participantIds],
    ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
    ...(keyRef.routerAbEcdsaDerivationNormalSigning
      ? { routerAbEcdsaDerivationNormalSigning: keyRef.routerAbEcdsaDerivationNormalSigning }
      : {}),
    thresholdSessionKind: keyRef.thresholdSessionKind,
    thresholdSessionId: keyRef.thresholdSessionId,
    signingGrantId: keyRef.signingGrantId,
    ...(keyRef.walletSessionJwt ? { walletSessionJwt: keyRef.walletSessionJwt } : {}),
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    thresholdEcdsaPublicKeyB64u: keyRef.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: keyRef.ethereumAddress,
    relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
    updatedAtMs: args.updatedAtMs ?? Date.now(),
  };
}

/**
 * Builds a canonical Email OTP ThresholdEcdsaSessionRecord (inline role-local material)
 * through the shared bootstrap fixture and the production record parser. Pure: does not
 * write any session store.
 */
export function buildEmailOtpEcdsaSessionRecordFixture(
  args: EcdsaSessionRecordFixtureSharedArgs & {
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    /** Email OTP worker-session handle id; defaults to the threshold session id. */
    workerSessionId?: string;
    /**
     * Where the role-local material lives: inline worker-session material (default) or a
     * worker-owned durable material reference.
     */
    material?: 'inline_worker_session' | 'worker_owned';
    roleLocalDurableMaterialRef?: string;
  },
): ThresholdEcdsaSessionRecord {
  const { chain, chainTarget } = ecdsaFixtureChainBinding(args);
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    ...ecdsaFixtureBootstrapArgs(args, chain),
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId:
      emailOtpAuthContextProviderUserId(args.emailOtpAuthContext) || `google:${args.walletId}`,
  });
  const raw = ecdsaSessionRecordRawFromBootstrapFixture({
    bootstrap,
    chainTarget,
    ...(args.updatedAtMs !== undefined ? { updatedAtMs: args.updatedAtMs } : {}),
  });
  const emailOtpAuthContext = requireEmailOtpFixtureAuthContext(args.emailOtpAuthContext);
  if (args.material === 'worker_owned') {
    const durableMaterialRef =
      args.roleLocalDurableMaterialRef ||
      `role-local-durable-${String(bootstrap.thresholdEcdsaKeyRef.thresholdSessionId)}`;
    return parseRawThresholdEcdsaSessionRecord({
      ...raw,
      roleLocalDurableMaterialRef: durableMaterialRef,
      emailOtpAuthContext,
      source: 'email_otp',
    });
  }
  const workerSessionId =
    args.workerSessionId || String(bootstrap.thresholdEcdsaKeyRef.thresholdSessionId);
  return parseRawThresholdEcdsaSessionRecord({
    ...raw,
    ecdsaRoleLocalReadyRecord: ecdsaFixtureReadyRecord(bootstrap),
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session',
      sessionId: workerSessionId,
    },
    emailOtpAuthContext,
    source: 'email_otp',
  });
}

/**
 * Builds a canonical passkey ThresholdEcdsaSessionRecord (worker-owned durable role-local
 * material) through the shared bootstrap fixture and the production record parser, and
 * binds a live role-local material handle so material classification can reach `ready`.
 */
export function buildPasskeyEcdsaSessionRecordFixture(
  args: EcdsaSessionRecordFixtureSharedArgs & {
    rpId?: string;
    passkeyCredentialIdB64u?: string;
    source?: 'login' | 'registration' | 'manual-bootstrap';
    roleLocalDurableMaterialRef?: string;
  },
): ThresholdEcdsaSessionRecord {
  const { chain, chainTarget } = ecdsaFixtureChainBinding(args);
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    ...ecdsaFixtureBootstrapArgs(args, chain),
    roleLocalAuthMethod: 'passkey',
    ...(args.rpId ? { rpId: args.rpId } : {}),
    ...(args.passkeyCredentialIdB64u
      ? { passkeyCredentialIdB64u: args.passkeyCredentialIdB64u }
      : {}),
  });
  const durableMaterialRef =
    args.roleLocalDurableMaterialRef ||
    `role-local-durable-${String(bootstrap.thresholdEcdsaKeyRef.thresholdSessionId)}`;
  const record = parseRawThresholdEcdsaSessionRecord({
    ...ecdsaSessionRecordRawFromBootstrapFixture({
      bootstrap,
      chainTarget,
      ...(args.updatedAtMs !== undefined ? { updatedAtMs: args.updatedAtMs } : {}),
    }),
    roleLocalDurableMaterialRef: durableMaterialRef,
    source: args.source || 'login',
  });
  const persistedMaterial = buildPersistedEcdsaRoleLocalMaterial({
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(durableMaterialRef),
    publicFacts: record.ecdsaRoleLocalPublicFacts,
  });
  bindLiveEcdsaRoleLocalMaterial({
    persistedMaterial,
    liveHandle: parseEcdsaRoleLocalWorkerHandle({
      kind: 'ecdsa_role_local_worker_handle_v1',
      materialHandle: `${durableMaterialRef}:live`,
      bindingDigest: record.ecdsaRoleLocalPublicFacts.contextBinding32B64u,
      durableMaterialRef,
    }),
  });
  return record;
}

function roleLocalKeyRecordBytesB64u(length: number, lastByte: number, firstByte = 0): string {
  const bytes = Buffer.alloc(length, 0);
  bytes[0] = firstByte;
  bytes[length - 1] = lastByte;
  return bytes.toString('base64url');
}

function roleLocalKeyRecordPublicKey33B64u(lastByte: number, prefix: 0x02 | 0x03 = 0x02): string {
  return roleLocalKeyRecordBytesB64u(33, lastByte, prefix);
}

/**
 * Builds a server-side role-local threshold ECDSA derivation key record through the
 * production `parseEcdsaDerivationRoleLocalKeyRecord` validator. `keyHandle` defaults to
 * the canonical derived handle for the key identity.
 */
export async function makeEcdsaDerivationRoleLocalKeyRecord(
  overrides: Partial<EcdsaDerivationRoleLocalKeyRecord> = {},
): Promise<EcdsaDerivationRoleLocalKeyRecord> {
  const walletId = 'alice.testnet';
  const signingRootId = 'signing-root';
  const signingRootVersion = 'default';
  const base = {
    version: 'threshold_ecdsa_derivation_role_local_v2',
    ecdsaThresholdKeyId: 'threshold-key',
    walletId,
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId,
      signingRootId,
      signingRootVersion,
    }),
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId: 'relayer-key',
    contextBinding32B64u: roleLocalKeyRecordBytesB64u(32, 1),
    relayerShare32B64u: roleLocalKeyRecordBytesB64u(32, 2),
    relayerPublicKey33B64u: roleLocalKeyRecordPublicKey33B64u(3),
    clientPublicKey33B64u: roleLocalKeyRecordPublicKey33B64u(4, 0x03),
    groupPublicKey33B64u: roleLocalKeyRecordPublicKey33B64u(5),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    publicTranscriptDigest32B64u: roleLocalKeyRecordBytesB64u(32, 8),
    createdAtMs: 100,
    updatedAtMs: 200,
    ...overrides,
  } satisfies Omit<EcdsaDerivationRoleLocalKeyRecord, 'keyHandle'> & { keyHandle?: string };
  const keyHandle =
    overrides.keyHandle ??
    String(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId: base.ecdsaThresholdKeyId,
        signingRootId: base.signingRootId,
        signingRootVersion: base.signingRootVersion,
      }),
    );
  const parsed = parseEcdsaDerivationRoleLocalKeyRecord({ ...base, keyHandle });
  if (!parsed) {
    throw new Error('fixture must produce a role-local threshold ECDSA key record');
  }
  return parsed;
}
