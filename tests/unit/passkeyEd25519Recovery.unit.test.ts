import { expect, test } from '@playwright/test';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  upsertStoredThresholdEd25519SessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { reconnectPasskeyEd25519CapabilityForSigning } from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';

const ACCOUNT_ID = 'ed25519-reconnect-race.testnet';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'ed25519:relayer-key';
const PARTICIPANT_IDS = [1, 2, 3];
const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'credential-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: Buffer.alloc(32, 7).toString('base64url'),
        second: undefined,
      },
    },
  },
};

function writeEd25519Record(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
}) {
  const record = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: ACCOUNT_ID,
    rpId: RP_ID,
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: PARTICIPANT_IDS,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: `jwt:${args.thresholdSessionId}`,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 1,
    source: 'login',
  });
  if (!record) throw new Error('expected Ed25519 test record');
  return record;
}

test.describe('passkey Ed25519 reconnect recovery', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('retains exact Ed25519 lane records when another account record becomes current', () => {
    const planned = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-planned',
      signingGrantId: 'wsess-ed25519-planned',
    });
    const competing = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-competing',
      signingGrantId: 'wsess-ed25519-competing',
    });

    expect(getStoredThresholdEd25519SessionRecordForAccount(ACCOUNT_ID)?.thresholdSessionId).toBe(
      competing.thresholdSessionId,
    );
    expect(
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(planned.thresholdSessionId)
        ?.signingGrantId,
    ).toBe(planned.signingGrantId);
  });

  test('returns the exact planned reconnect record after a concurrent current-record update', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-old',
      signingGrantId: 'wsess-ed25519-old',
      remainingUses: 0,
    });
    const plannedSessionId = 'tsess-ed25519-planned-reconnect';
    const plannedSigningGrantId = 'wsess-ed25519-planned-reconnect';
    const competingSessionId = 'tsess-ed25519-competing-current';

    const result = await reconnectPasskeyEd25519CapabilityForSigning({
      nearAccountId: ACCOUNT_ID,
      record: oldRecord,
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: TEST_WEBAUTHN_CREDENTIAL as any,
        rpId: RP_ID,
      }),
      remainingUses: 1,
      sessionId: plannedSessionId,
      signingGrantId: plannedSigningGrantId,
      provisionThresholdEd25519Session: async (request) => {
        expect(request.kind).toBe('exact_ed25519_provisioning');
        expect(request.sessionId).toBe(plannedSessionId);
        expect(request.signingGrantId).toBe(plannedSigningGrantId);
        writeEd25519Record({
          thresholdSessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
        });
        writeEd25519Record({
          thresholdSessionId: competingSessionId,
          signingGrantId: 'wsess-ed25519-competing-current',
        });
        return {
          ok: true,
          sessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          jwt: `jwt:${plannedSessionId}`,
        };
      },
    });

    expect(result.sessionId).toBe(plannedSessionId);
    expect(result.record?.thresholdSessionId).toBe(plannedSessionId);
    expect(result.record?.signingGrantId).toBe(plannedSigningGrantId);
    expect(getStoredThresholdEd25519SessionRecordForAccount(ACCOUNT_ID)?.thresholdSessionId).toBe(
      competingSessionId,
    );
  });
});
