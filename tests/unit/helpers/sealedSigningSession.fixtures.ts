import {
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  requireAuthoritativeExpiredWalletSessionAuthorizationBoundary,
  type ExpiredWalletSessionAuthorizationState,
} from '@/core/signingEngine/session/identity/clientSessionPersistenceState';
import type { ExactSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { createThresholdEcdsaBootstrapFixture } from './ecdsaBootstrap.fixtures';

export type EmailOtpEcdsaSealedSigningSessionRecord = Extract<
  SealedSigningSessionRecord,
  { curve: 'ecdsa' }
>;

export type EmailOtpEcdsaSealedRestorePayload = NonNullable<
  EmailOtpEcdsaSealedSigningSessionRecord['ecdsaRestore']
>;

type EmailOtpEcdsaSealedFixtureParts = {
  walletId: string;
  signingGrantId: string;
  thresholdSessionId: string;
  relayerUrl: string;
  restore: EmailOtpEcdsaSealedRestorePayload;
};

/**
 * Wallet Session JWT accepted by the sealed store's current-record
 * classification (`isCurrentThresholdEcdsaSessionJwt` requires the Router A/B
 * ECDSA kind plus matching `walletId` and `keyHandle` claims).
 */
function fixtureSealedEcdsaWalletSessionJwt(args: {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return [
    encode({ alg: 'none', typ: 'JWT' }),
    encode({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      sub: args.walletId,
      walletId: args.walletId,
      keyHandle: args.keyHandle,
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      thresholdExpiresAtMs: Date.now() + 120_000,
    }),
    'fixture',
  ].join('.');
}

function emailOtpEcdsaSealedFixtureParts(
  args: { walletId?: string } = {},
): EmailOtpEcdsaSealedFixtureParts {
  const walletId = args.walletId ?? 'alice.testnet';
  const providerSubjectId = `google:${walletId.split('.')[0]}`;
  const signingGrantId = 'wallet-session-1';
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: walletId,
    chain: 'tempo',
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId: providerSubjectId,
    signingRootId: 'root',
    signingRootVersion: 'v1',
    keyHandle: 'key-handle',
    relayerKeyId: 'relayer-key',
    sessionId: 'ec-session',
    signingGrantId,
    walletSessionJwt: fixtureSealedEcdsaWalletSessionJwt({
      walletId,
      keyHandle: 'key-handle',
      thresholdSessionId: 'ec-session',
      signingGrantId,
    }),
  });
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const backendBinding = keyRef.backendBinding;
  if (backendBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('Sealed-session fixture requires a role-local ready ECDSA backend binding');
  }
  const routerAbEcdsaDerivationNormalSigning = keyRef.routerAbEcdsaDerivationNormalSigning;
  if (!routerAbEcdsaDerivationNormalSigning) {
    throw new Error('Sealed-session fixture requires Router A/B ECDSA normal-signing state');
  }
  if (!keyRef.walletSessionJwt || !keyRef.keyHandle || !keyRef.ethereumAddress) {
    throw new Error('Sealed-session fixture requires JWT wallet-session bootstrap facts');
  }
  return {
    walletId,
    signingGrantId,
    thresholdSessionId: keyRef.thresholdSessionId,
    relayerUrl: keyRef.relayerUrl,
    restore: {
      chainTarget: keyRef.chainTarget,
      source: 'email_otp',
      evmFamilySigningKeySlotId: keyRef.evmFamilySigningKeySlotId,
      signingRootId: 'root',
      signingRootVersion: 'v1',
      provider: 'google',
      providerSubjectId,
      emailHashHex: 'email-hash',
      sessionKind: 'jwt',
      walletSessionJwt: keyRef.walletSessionJwt,
      keyHandle: keyRef.keyHandle,
      ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
      ethereumAddress: keyRef.ethereumAddress,
      relayerKeyId: backendBinding.relayerKeyId,
      roleLocalDurableMaterialRef: 'role-local-material',
      participantIds: [...(keyRef.participantIds || [1, 2])],
      routerAbEcdsaDerivationNormalSigning,
      publicCapability: backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.publicCapability,
    },
  };
}

/**
 * Email OTP + ECDSA sealed restore payload (the `ecdsaRestore` sub-object of a
 * current sealed signing-session record), for tests that drive the production
 * `buildCurrentSealedSessionRecord` path with per-test session identity. The
 * embedded Wallet Session JWT claims follow `walletId`, which must match the
 * sealed record's `walletId` for current-record classification.
 */
export function seedEmailOtpEcdsaSealedRestorePayload(
  args: { walletId?: string } & Partial<EmailOtpEcdsaSealedRestorePayload> = {},
): EmailOtpEcdsaSealedRestorePayload {
  const { walletId, ...overrides } = args;
  // Cast: spreading Partial overrides over the sessionKind-discriminated restore
  // union defeats TS narrowing; the base payload is always the jwt/email_otp arm
  // and overrides only vary the fields a test exercises.
  return {
    ...emailOtpEcdsaSealedFixtureParts({ walletId }).restore,
    ...overrides,
  } as EmailOtpEcdsaSealedRestorePayload;
}

/**
 * Email OTP + ECDSA sealed signing-session record on the current
 * `SealedSigningSessionRecord` shape (mirrors the canonical type fixture in
 * `packages/shared-ts/src/utils/signingSessionSeal.typecheck.ts`). The Router A/B
 * ECDSA normal-signing state and public capability come from the shared bootstrap
 * fixture, which builds them through the production parse functions.
 */
export function seedEmailOtpEcdsaSealedSigningSessionRecord(
  overrides: Partial<EmailOtpEcdsaSealedSigningSessionRecord> = {},
): EmailOtpEcdsaSealedSigningSessionRecord {
  const { walletId, signingGrantId, thresholdSessionId, relayerUrl, restore } =
    emailOtpEcdsaSealedFixtureParts();
  const record: EmailOtpEcdsaSealedSigningSessionRecord = {
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod: 'email_otp',
    secretKind: SIGNING_SESSION_SECRET_KIND,
    storeKey: `${signingGrantId}:email_otp:ecdsa`,
    signingGrantId,
    thresholdSessionIds: {
      ecdsa: thresholdSessionId,
    },
    sealedSecretB64u: 'sealed-k',
    curve: 'ecdsa',
    walletId,
    relayerUrl,
    ecdsaRestore: restore,
    keyVersion: 'signing-session-seal-kek-test-r1',
    shamirPrimeB64u: 'prime',
    issuedAtMs: 1,
    expiresAtMs: 2,
    remainingUses: 3,
    updatedAtMs: 4,
  };
  return { ...record, ...overrides };
}

/**
 * Expired Wallet Session authorization state built through the production
 * boundary parser, so identity fields (walletId, walletSessionId, authMethod)
 * always derive from the supplied lane identity.
 */
export function seedExpiredWalletSessionAuthorizationState(args: {
  identity: ExactSigningLaneIdentity;
  expiresAtMs?: number;
  detectedAtMs?: number;
}): ExpiredWalletSessionAuthorizationState {
  const expiresAtMs = args.expiresAtMs ?? 1_000;
  return requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
    identity: args.identity,
    expiresAtMs,
    detectedAtMs: args.detectedAtMs ?? expiresAtMs + 1,
  });
}
