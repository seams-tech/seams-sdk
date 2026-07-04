import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
  type ThresholdEd25519UpsertMaterialFields,
  upsertStoredThresholdEd25519SessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
} from '@/core/signingEngine/session/persistence/records';
import {
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
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
  runtimeValidated?: boolean;
};

function assertNever(value: never): never {
  throw new Error(`Unexpected fixture branch: ${String(value)}`);
}

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
  const record = upsertStoredThresholdEd25519SessionRecord({
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    rpId: args.rpId || 'wallet.example.test',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    relayerKeyId,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...thresholdEd25519FixtureMaterialFields(args),
    ...(args.signerSlot !== 0 ? { signerSlot: args.signerSlot || 1 } : {}),
    ...(args.keyVersion !== ''
      ? { keyVersion: args.keyVersion || 'threshold-ed25519-hss-v1' }
      : {}),
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
          source: 'email_otp',
          emailOtpAuthContext: requireEmailOtpFixtureAuthContext(emailOtpAuthContext),
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

function thresholdEd25519FixtureMaterialFields(
  args: SeedEd25519WarmSessionRecordArgs,
): ThresholdEd25519UpsertMaterialFields {
  const materialState = args.materialState || 'material_ready';
  switch (materialState) {
    case 'auth_ready_material_pending':
      return {};
    case 'restore_available':
      return {
        clientVerifyingShareB64u: args.clientVerifyingShareB64u || 'fixture-client-verifier',
        ed25519WorkerMaterialBindingDigest:
          args.ed25519WorkerMaterialBindingDigest || 'fixture-binding',
        sealedWorkerMaterialRef:
          args.sealedWorkerMaterialRef ||
          `ed25519-worker-material-v1:${args.thresholdSessionId}:fixture-binding`,
        ...(args.sealedWorkerMaterialB64u
          ? { sealedWorkerMaterialB64u: args.sealedWorkerMaterialB64u }
          : {}),
        materialFormatVersion: args.materialFormatVersion || 'ed25519_worker_material_v1',
        materialKeyId: args.materialKeyId || `material-key-${args.thresholdSessionId}`,
        materialCreatedAtMs: args.materialCreatedAtMs || 1_700_000_000_000,
      };
    case 'material_ready':
      return {
        clientVerifyingShareB64u: args.clientVerifyingShareB64u || 'fixture-client-verifier',
        ed25519WorkerMaterialHandle:
          args.ed25519WorkerMaterialHandle ||
          `ed25519-worker-material:${args.thresholdSessionId}:fixture-binding`,
        ed25519WorkerMaterialBindingDigest:
          args.ed25519WorkerMaterialBindingDigest || 'fixture-binding',
        sealedWorkerMaterialRef:
          args.sealedWorkerMaterialRef ||
          `ed25519-worker-material-v1:${args.thresholdSessionId}:fixture-binding`,
        sealedWorkerMaterialB64u: args.sealedWorkerMaterialB64u || 'fixture-sealed-material',
        materialFormatVersion: args.materialFormatVersion || 'ed25519_worker_material_v1',
        materialKeyId: args.materialKeyId || `material-key-${args.thresholdSessionId}`,
        materialCreatedAtMs: args.materialCreatedAtMs || 1_700_000_000_000,
      };
    default:
      return assertNever(materialState);
  }
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
