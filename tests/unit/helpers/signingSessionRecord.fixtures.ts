import {
  clearAllStoredThresholdEd25519SessionRecords,
  type ThresholdEd25519SessionRecord,
  upsertThresholdEd25519SessionFact,
} from '@/core/signingEngine/session/persistence/records';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { parseEcdsaDerivationRoleLocalKeyRecord } from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { EcdsaDerivationRoleLocalKeyRecord } from '../../../packages/sdk-server-ts/src/core/types';
import { fixtureRuntimePolicyScopeFromSigningRoot } from './ecdsaBootstrap.fixtures';

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

export function resetWarmSessionFixtureState(): void {
  ensureWarmSessionTestStorage().clear();
  clearAllStoredThresholdEd25519SessionRecords();
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
    runtimePolicyScope,
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

function roleLocalKeyRecordBytesB64u(length: number, lastByte: number, firstByte = 0): string {
  const bytes = Buffer.alloc(length, 0);
  bytes[0] = firstByte;
  bytes[length - 1] = lastByte;
  return bytes.toString('base64url');
}

function roleLocalKeyRecordPublicKey33B64u(lastByte: number, prefix: 0x02 | 0x03 = 0x02): string {
  return roleLocalKeyRecordBytesB64u(33, lastByte, prefix);
}

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
