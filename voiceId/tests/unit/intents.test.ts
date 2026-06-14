import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildVoiceIdIntentDigest,
  buildVoiceIdRobotCommandIntent,
  buildVoiceIdSpokenIntentBinding,
  buildVoiceIdTokenTransferIntent,
  buildVoiceIdWalletSessionIntent,
  canonicalizeVoiceIdIntent,
  parseIsoDateTime,
  parseVoiceIdIntentDeviceId,
  parseVoiceIdIntentNonce,
  parseVoiceIdPaymentRecipient,
  parseVoiceIdRobotCommandText,
  parseVoiceIdSpokenIntentCommand,
  parseVoiceIdTokenAmount,
  parseVoiceIdTokenSymbol,
} from '../../shared/src/index.ts';

const expiresAt = parseIsoDateTime('2026-06-13T00:05:00.000Z');
const nonce = parseVoiceIdIntentNonce('nonce_123456');

test('parses spoken token transfer intents', () => {
  const intent = parseVoiceIdSpokenIntentCommand({
    spokenCommand: 'Send 1 USDC to Bob',
    expiresAt,
    nonce,
  });

  assert.deepEqual(intent, {
    kind: 'token_transfer',
    schemaVersion: 'voice_id_intent_v1',
    amount: '1',
    tokenSymbol: 'USDC',
    recipient: 'bob',
    expiresAt,
    nonce,
  });

  assert.deepEqual(
    parseVoiceIdSpokenIntentCommand({
      spokenCommand: 'send 50 USDC to bob.near',
      expiresAt,
      nonce,
    }),
    {
      kind: 'token_transfer',
      schemaVersion: 'voice_id_intent_v1',
      amount: '50',
      tokenSymbol: 'USDC',
      recipient: 'bob.near',
      expiresAt,
      nonce,
    },
  );
});

test('parses spoken wallet-session and robot-command intents', () => {
  assert.deepEqual(
    parseVoiceIdSpokenIntentCommand({
      spokenCommand: 'Authorize wallet session for device X',
      expiresAt,
      nonce,
    }),
    {
      kind: 'wallet_session',
      schemaVersion: 'voice_id_intent_v1',
      deviceId: 'x',
      expiresAt,
      nonce,
    },
  );

  assert.deepEqual(
    parseVoiceIdSpokenIntentCommand({
      spokenCommand: 'command robot to stir the pot',
      expiresAt,
      nonce,
    }),
    {
      kind: 'robot_command',
      schemaVersion: 'voice_id_intent_v1',
      command: 'stir the pot',
      expiresAt,
      nonce,
    },
  );
});

test('canonicalizes intents with stable field order', () => {
  const transfer = buildVoiceIdTokenTransferIntent({
    amount: parseVoiceIdTokenAmount('001.5000'),
    tokenSymbol: parseVoiceIdTokenSymbol('usdc'),
    recipient: parseVoiceIdPaymentRecipient('Bob.NEAR'),
    expiresAt,
    nonce,
  });
  const walletSession = buildVoiceIdWalletSessionIntent({
    deviceId: parseVoiceIdIntentDeviceId('Device-X'),
    expiresAt,
    nonce,
  });
  const robotCommand = buildVoiceIdRobotCommandIntent({
    command: parseVoiceIdRobotCommandText('Stir the pot'),
    expiresAt,
    nonce,
  });

  assert.equal(
    canonicalizeVoiceIdIntent(transfer),
    '{"schemaVersion":"voice_id_intent_v1","kind":"token_transfer","amount":"1.5","tokenSymbol":"USDC","recipient":"bob.near","expiresAt":"2026-06-13T00:05:00.000Z","nonce":"nonce_123456"}',
  );
  assert.equal(
    canonicalizeVoiceIdIntent(walletSession),
    '{"schemaVersion":"voice_id_intent_v1","kind":"wallet_session","deviceId":"device-x","expiresAt":"2026-06-13T00:05:00.000Z","nonce":"nonce_123456"}',
  );
  assert.equal(
    canonicalizeVoiceIdIntent(robotCommand),
    '{"schemaVersion":"voice_id_intent_v1","kind":"robot_command","command":"stir the pot","expiresAt":"2026-06-13T00:05:00.000Z","nonce":"nonce_123456"}',
  );
});

test('builds stable intent digests and changes digest when intent fields change', async () => {
  const first = parseVoiceIdSpokenIntentCommand({
    spokenCommand: 'Send 1 USDC to Bob',
    expiresAt,
    nonce,
  });
  const same = parseVoiceIdSpokenIntentCommand({
    spokenCommand: 'send 001.00 usdc to bob',
    expiresAt,
    nonce,
  });
  const differentAmount = parseVoiceIdSpokenIntentCommand({
    spokenCommand: 'send 2 USDC to Bob',
    expiresAt,
    nonce,
  });
  const differentExpiry = parseVoiceIdSpokenIntentCommand({
    spokenCommand: 'Send 1 USDC to Bob',
    expiresAt: '2026-06-13T00:06:00.000Z',
    nonce,
  });

  const firstDigest = await buildVoiceIdIntentDigest(first);
  assert.match(firstDigest, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await buildVoiceIdIntentDigest(same), firstDigest);
  assert.notEqual(await buildVoiceIdIntentDigest(differentAmount), firstDigest);
  assert.notEqual(await buildVoiceIdIntentDigest(differentExpiry), firstDigest);
});

test('builds spoken intent bindings with normalized command and digest', async () => {
  const binding = await buildVoiceIdSpokenIntentBinding({
    spokenCommand: 'Send 50 USDC to bob.near',
    expiresAt,
    nonce,
  });

  assert.equal(binding.kind, 'voice_id_spoken_intent_binding_v1');
  assert.equal(binding.normalizedCommand, 'send 50 usdc to bob.near');
  assert.equal(binding.intent.kind, 'token_transfer');
  assert.match(binding.intentDigest, /^[A-Za-z0-9_-]{43}$/);
});

test('rejects unsupported or malformed spoken commands', () => {
  assert.throws(
    () =>
      parseVoiceIdSpokenIntentCommand({
        spokenCommand: 'send USDC to Bob',
        expiresAt,
        nonce,
      }),
    /supported VoiceID intent/,
  );
  assert.throws(
    () =>
      parseVoiceIdSpokenIntentCommand({
        spokenCommand: 'delete everything',
        expiresAt,
        nonce,
      }),
    /supported VoiceID intent/,
  );
  assert.throws(() => parseVoiceIdTokenAmount('0'), /greater than zero/);
  assert.throws(() => parseVoiceIdIntentNonce('short'), /intent nonce/);
});
