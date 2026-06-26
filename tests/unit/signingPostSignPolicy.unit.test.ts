import { expect, test } from '@playwright/test';
import { SENSITIVE_OPERATION_POLICIES } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  applyEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed,
  ecdsaPostSignPolicySessionFromRecord,
  secondaryEcdsaPostSignPolicyMaterialFromRecord,
  selectedEcdsaPostSignPolicyMaterialFromRecord,
} from '@/core/signingEngine/session/operationState/postSignPolicy';
import type { ConsumeSingleUseEmailOtpEcdsaLaneCommand } from '@/core/signingEngine/session/persistence/records';
import { toEvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

const WALLET_ID = toWalletId('alice.testnet');
const EVM_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};
const TEMPO_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 1,
  networkSlug: 'tempo-mainnet',
};
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_CONTEXT_BINDING_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const POST_SIGN_PASSKEY_CREDENTIAL_ID = 'post-sign-passkey-credential';

function roleLocalReadyRecordForPostSign(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  source: 'email_otp' | 'login';
}) {
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-post-sign');
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_CONTEXT_BINDING_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: WALLET_ID,
      walletKeyId: 'wallet-key-post-sign',
      rpId: 'localhost',
      chainTarget: args.chainTarget,
      keyHandle,
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: 'signing-root',
      signingRootVersion: 'v1',
      applicationBindingDigestB64u: VALID_CONTEXT_BINDING_B64U,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: VALID_CONTEXT_BINDING_B64U,
      hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    }),
    authMethod:
      args.source === 'email_otp'
        ? buildEcdsaRoleLocalEmailOtpAuthMethod({ authSubjectId: String(WALLET_ID) })
        : buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: POST_SIGN_PASSKEY_CREDENTIAL_ID,
            rpId: 'localhost',
          }),
  });
}

function ecdsaRecord(args: {
  thresholdSessionId: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  source?: 'email_otp' | 'login';
  retention?: 'session' | 'single_use';
  consumedAtMs?: number;
}): ThresholdEcdsaSessionRecord {
  const source = args.source || 'email_otp';
  const chainTarget = args.chainTarget || EVM_CHAIN_TARGET;
  const common = {
    walletId: WALLET_ID,
    walletKeyId: 'localhost',
    chainTarget,
    relayerUrl: 'https://relay.example',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-post-sign'),
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'signing-root',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
    ecdsaRoleLocalReadyRecord: roleLocalReadyRecordForPostSign({ chainTarget, source }),
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt' as const,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: `wallet-${args.thresholdSessionId}`,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    updatedAtMs: Date.now(),
  };
  if (source === 'login') {
    return {
      ...common,
      source: 'login',
    };
  }
  return {
    ...common,
    source: 'email_otp',
    emailOtpAuthContext: {
      authMethod: 'email_otp',
      authSubjectId: String(WALLET_ID),
      policy: 'per_operation',
      reason: 'sign',
      retention: args.retention || 'single_use',
      ...(args.consumedAtMs ? { consumedAtMs: args.consumedAtMs } : {}),
    },
  };
}

test.describe('SigningPostSignPolicy', () => {
  test('clears single-use selected Email OTP material and marks the lane consumed', async () => {
    const consumed: Array<{
      command: ConsumeSingleUseEmailOtpEcdsaLaneCommand;
    }> = [];
    const cleared: Array<{
      recordThresholdSessionId: string;
      thresholdSessionId: string;
    }> = [];
    const selectedRecord = ecdsaRecord({ thresholdSessionId: 'otp-session' });

    await applyEcdsaPostSignPolicy({
      source: null,
      thresholdSessionId: 'otp-session',
      selectedMaterial: selectedEcdsaPostSignPolicyMaterialFromRecord({
        record: selectedRecord,
        clearEcdsaEphemeralMaterial: async (args) => {
          cleared.push({
            recordThresholdSessionId: args.record.thresholdSessionId,
            thresholdSessionId: args.thresholdSessionId || '',
          });
        },
      }),
      secondaryMaterial: null,
      consumeSingleUseEmailOtpEcdsaLane: (command) => {
        consumed.push({ command });
        return {
          kind: 'consumed',
          laneKey: command.lane.laneRef.laneKey,
          consumedAtMs: 1,
        };
      },
    });

    expect(consumed).toHaveLength(1);
    expect(consumed[0]?.command.kind).toBe('consume_single_use_email_otp_ecdsa_lane');
    expect(consumed[0]?.command.uses).toBe(1);
    expect(consumed[0]?.command.lane.laneRef.exactIdentity.signer.walletId).toBe(
      WALLET_ID,
    );
    expect(consumed[0]?.command.lane.laneRef.exactIdentity.signer.chainTarget).toEqual(EVM_CHAIN_TARGET);
    expect(consumed[0]?.command.lane.laneRef.exactIdentity.signingGrantId).toBe(
      'wallet-otp-session',
    );
    expect(consumed[0]?.command.lane.laneRef.exactIdentity.thresholdSessionId).toBe('otp-session');
    expect(cleared).toEqual([
      {
        recordThresholdSessionId: 'otp-session',
        thresholdSessionId: 'otp-session',
      },
    ]);
  });

  test('does not consume or clear secondary Email OTP material when the selected lane is passkey', async () => {
    const consumed: ConsumeSingleUseEmailOtpEcdsaLaneCommand[] = [];
    const cleared: Array<{
      recordThresholdSessionId: string;
      thresholdSessionId: string;
    }> = [];
    const selectedRecord = ecdsaRecord({
      chainTarget: TEMPO_CHAIN_TARGET,
      thresholdSessionId: 'passkey-session',
      source: 'login',
    });
    const secondaryRecord = ecdsaRecord({
      chainTarget: TEMPO_CHAIN_TARGET,
      thresholdSessionId: 'otp-session',
    });

    await applyEcdsaPostSignPolicy({
      source: null,
      thresholdSessionId: null,
      selectedMaterial: selectedEcdsaPostSignPolicyMaterialFromRecord({
        record: selectedRecord,
        clearEcdsaEphemeralMaterial: async () => {},
      }),
      secondaryMaterial: secondaryEcdsaPostSignPolicyMaterialFromRecord({
        record: secondaryRecord,
        clearEcdsaEphemeralMaterial: async (args) => {
          cleared.push({
            recordThresholdSessionId: args.record.thresholdSessionId,
            thresholdSessionId: args.thresholdSessionId || '',
          });
        },
      }),
      consumeSingleUseEmailOtpEcdsaLane: (command) => {
        consumed.push(command);
        return {
          kind: 'consumed',
          laneKey: command.lane.laneRef.laneKey,
          consumedAtMs: 1,
        };
      },
    });

    expect(consumed).toEqual([]);
    expect(cleared).toEqual([]);
  });

  test('blocks consumed single-use Email OTP sensitive operations', () => {
    expect(() =>
      assertEcdsaOperationAllowed({
        chainTarget: EVM_CHAIN_TARGET,
        operationLabel: 'evm signing',
        thresholdSessionId: null,
        source: null,
        selectedSession: ecdsaPostSignPolicySessionFromRecord(
          ecdsaRecord({
            thresholdSessionId: 'otp-session',
            consumedAtMs: Date.now(),
          }),
        ),
        secondarySession: null,
      }),
    ).toThrow(/fresh Email OTP/i);
  });

  test('requires passkey when sensitive policy denies Email OTP', () => {
    expect(() =>
      assertEcdsaOperationAllowed({
        chainTarget: EVM_CHAIN_TARGET,
        operationLabel: 'evm signing',
        thresholdSessionId: null,
        source: null,
        selectedSession: ecdsaPostSignPolicySessionFromRecord(
          ecdsaRecord({
            thresholdSessionId: 'otp-session',
            retention: 'session',
          }),
        ),
        secondarySession: null,
        sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requirePasskey,
      }),
    ).toThrow(/passkey/i);
  });
});
