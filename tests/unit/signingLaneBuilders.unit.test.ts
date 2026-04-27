import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  buildEvmTransactionSigningLane,
  buildNearTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/signingSession/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';

const baseInput = {
  accountId: toAccountId('lane-builder.testnet'),
  walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-build-1'),
  signingRootId: 'proj_lane:dev',
  signingRootVersion: 'default',
};

test.describe('SigningLaneBuilders', () => {
  test('builds NEAR Email OTP lanes as Ed25519 threshold lanes', () => {
    const lane = buildNearTransactionSigningLane({
      ...baseInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-ed25519-build'),
      retention: 'single_use',
    });

    expect(lane).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      keyKind: 'threshold_ed25519',
      chainFamily: 'near',
      storageSource: 'email_otp',
      sessionOrigin: 'per_operation',
      retention: 'single_use',
    });
  });

  test('builds NEAR passkey lanes from passkey storage sources', () => {
    const lane = buildNearTransactionSigningLane({
      ...baseInput,
      authMethod: 'passkey',
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-ed25519-passkey'),
      storageSource: 'manual-connect',
    });

    expect(lane).toMatchObject({
      authMethod: 'passkey',
      curve: 'ed25519',
      keyKind: 'threshold_ed25519',
      chainFamily: 'near',
      storageSource: 'manual-connect',
      sessionOrigin: 'manual_connect',
      retention: 'session',
    });
  });

  test('builds Tempo Email OTP and passkey lanes as ECDSA threshold lanes', () => {
    const emailOtpLane = buildTempoTransactionSigningLane({
      ...baseInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-tempo-otp'),
      sessionOrigin: 'login',
    });
    const passkeyLane = buildTempoTransactionSigningLane({
      ...baseInput,
      authMethod: 'passkey',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-tempo-passkey'),
      storageSource: 'registration',
    });

    expect(emailOtpLane).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      keyKind: 'threshold_ecdsa_secp256k1',
      chainFamily: 'tempo',
      storageSource: 'email_otp',
      sessionOrigin: 'login',
    });
    expect(passkeyLane).toMatchObject({
      authMethod: 'passkey',
      curve: 'ecdsa',
      keyKind: 'threshold_ecdsa_secp256k1',
      chainFamily: 'tempo',
      storageSource: 'registration',
      sessionOrigin: 'registration',
    });
  });

  test('builds EVM lanes without falling back to Tempo chain state', () => {
    const lane = buildEvmTransactionSigningLane({
      ...baseInput,
      authMethod: 'email_otp',
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-evm-otp'),
      backingMaterialSessionId: SigningSessionIds.backingMaterialSession('backing-evm-otp'),
    });

    expect(lane).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainFamily: 'evm',
      storageSource: 'email_otp',
      backingMaterialSessionId: 'backing-evm-otp',
    });
  });
});
