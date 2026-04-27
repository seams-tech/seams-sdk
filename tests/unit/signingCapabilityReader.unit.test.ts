import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  createSigningCapabilityReader,
  type SigningCapabilityReaderDeps,
} from '@/core/signingEngine/session/signingSession/lanes';
import {
  buildEvmTransactionSigningLane,
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { SigningSessionIds, type SigningLaneContext } from '@/core/signingEngine/session/signingSession/types';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';

const accountId = toAccountId('capability-reader.testnet');
const baseLaneInput = {
  accountId,
  walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-capability-reader'),
  signingRootId: 'proj_capability:dev',
  signingRootVersion: 'default',
};

test.describe('SigningCapabilityReader', () => {
  test('reads Email OTP ECDSA capability only through the Email OTP port', () => {
    const calls: string[] = [];
    const lane = buildTempoTransactionSigningLane({
      ...baseLaneInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-otp-ecdsa'),
    });
    const deps: SigningCapabilityReaderDeps = {
      readEmailOtpEcdsaSessionRecord: (args) => {
        calls.push(`otp-record:${args.chain}`);
        return makeEcdsaRecord(lane);
      },
      readEmailOtpEcdsaKeyRef: (args) => {
        calls.push(`otp-key:${args.chain}`);
        return makeEcdsaKeyRef(lane);
      },
      readPasskeyEcdsaSessionRecord: () => {
        throw new Error('passkey record port must not be called');
      },
      readPasskeyEcdsaKeyRef: () => {
        throw new Error('passkey key port must not be called');
      },
    };

    const result = createSigningCapabilityReader(deps).readCapability(lane);

    expect(result.ok).toBe(true);
    expect(result.ok && result.capability.curve).toBe('ecdsa');
    expect(result.ok && result.keyRef?.thresholdSessionId).toBe('tsess-otp-ecdsa');
    expect(calls).toEqual(['otp-record:tempo', 'otp-key:tempo']);
  });

  test('reads passkey ECDSA capability with the selected passkey storage source', () => {
    const calls: string[] = [];
    const lane = buildEvmTransactionSigningLane({
      ...baseLaneInput,
      authMethod: 'passkey',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-passkey-ecdsa'),
      storageSource: 'registration',
    });
    const deps: SigningCapabilityReaderDeps = {
      readPasskeyEcdsaSessionRecord: (args) => {
        calls.push(`passkey-record:${args.chain}:${args.storageSource}`);
        return makeEcdsaRecord(lane);
      },
      readPasskeyEcdsaKeyRef: (args) => {
        calls.push(`passkey-key:${args.chain}:${args.storageSource}`);
        return makeEcdsaKeyRef(lane);
      },
      readEmailOtpEcdsaSessionRecord: () => {
        throw new Error('Email OTP record port must not be called');
      },
      readEmailOtpEcdsaKeyRef: () => {
        throw new Error('Email OTP key port must not be called');
      },
    };

    const result = createSigningCapabilityReader(deps).readCapability(lane);

    expect(result.ok).toBe(true);
    expect(result.ok && result.capability.curve).toBe('ecdsa');
    expect(calls).toEqual(['passkey-record:evm:registration', 'passkey-key:evm:registration']);
  });

  test('rejects records that do not match the selected lane', () => {
    const lane = buildTempoTransactionSigningLane({
      ...baseLaneInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-selected'),
    });
    const result = createSigningCapabilityReader({
      readEmailOtpEcdsaSessionRecord: () =>
        makeEcdsaRecord(lane, {
          thresholdSessionId: 'tsess-other',
        }),
    }).readRecord(lane);

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message: 'Session record threshold session does not match selected lane',
    });
  });

  test('rejects key refs that do not match the selected wallet signing session', () => {
    const lane = buildTempoTransactionSigningLane({
      ...baseLaneInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-key-ref'),
    });
    const result = createSigningCapabilityReader({
      readEmailOtpEcdsaKeyRef: () =>
        makeEcdsaKeyRef(lane, {
          walletSigningSessionId: 'wsess-other',
        }),
    }).readEcdsaKeyRef(lane);

    expect(result).toMatchObject({
      ok: false,
      code: 'key_ref_mismatch',
      message: 'ECDSA key ref wallet signing session does not match selected lane',
    });
  });

  test('validates Ed25519 records against the selected lane source and wallet session', () => {
    const lane = buildNearTransactionSigningLane({
      ...baseLaneInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-ed25519-otp'),
    });
    const result = createSigningCapabilityReader({
      readEd25519SessionRecordByThresholdSessionId: () => makeEd25519Record(lane),
    }).readRecord(lane);

    expect(result.ok).toBe(true);
    expect(result.ok && result.capability.curve).toBe('ed25519');
    expect(result.ok && result.capability.record.source).toBe('email_otp');
  });

  test('rejects Ed25519 lane reads without a selected threshold session id', () => {
    const lane: SigningLaneContext = {
      ...buildNearTransactionSigningLane({
        ...baseLaneInput,
        authMethod: 'email_otp',
        thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-ed25519-present'),
      }),
      thresholdSessionId: undefined,
    };
    const result = createSigningCapabilityReader({
      readEd25519SessionRecordByThresholdSessionId: () => {
        throw new Error('session-scoped Ed25519 port must not be called');
      },
    }).readRecord(lane);

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message: 'Ed25519 signing lane requires threshold session id',
    });
  });
});

function makeEcdsaRecord(
  lane: SigningLaneContext,
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
): ThresholdEcdsaSessionRecord {
  return {
    nearAccountId: lane.accountId,
    chain: lane.chainFamily === 'evm' ? 'evm' : 'tempo',
    relayerUrl: 'https://relayer.test',
    ecdsaThresholdKeyId: 'ehss-test',
    signingRootId: lane.signingRootId || 'proj_capability:dev',
    signingRootVersion: lane.signingRootVersion,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-share',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: String(lane.thresholdSessionId || 'tsess-ecdsa'),
    walletSigningSessionId: String(lane.walletSigningSessionId),
    thresholdSessionJwt: 'jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    updatedAtMs: Date.now(),
    source: lane.storageSource as ThresholdEcdsaSessionRecord['source'],
    ...overrides,
  };
}

function makeEd25519Record(
  lane: SigningLaneContext,
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  return {
    nearAccountId: lane.accountId,
    rpId: 'localhost',
    relayerUrl: 'https://relayer.test',
    relayerKeyId: 'ed25519:relayer-key',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: String(lane.thresholdSessionId || 'tsess-ed25519'),
    walletSigningSessionId: String(lane.walletSigningSessionId),
    thresholdSessionJwt: 'jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    updatedAtMs: Date.now(),
    source: lane.storageSource as ThresholdEd25519SessionRecord['source'],
    ...overrides,
  };
}

function makeEcdsaKeyRef(
  lane: SigningLaneContext,
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(lane.accountId),
    relayerUrl: 'https://relayer.test',
    ecdsaThresholdKeyId: 'ehss-test',
    signingRootId: lane.signingRootId || 'proj_capability:dev',
    signingRootVersion: lane.signingRootVersion,
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: String(lane.thresholdSessionId || 'tsess-ecdsa'),
    walletSigningSessionId: String(lane.walletSigningSessionId),
    thresholdSessionJwt: 'jwt',
    ...overrides,
  };
}
