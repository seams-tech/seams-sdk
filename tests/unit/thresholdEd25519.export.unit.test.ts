import { expect, test } from '@playwright/test';
import {
  createThresholdSigningServiceForUnitTests,
  silentLogger,
} from '../helpers/thresholdEd25519TestUtils';
import {
  destroyPaillierKeyPair,
  generatePaillierKeyPair,
  paillierEncrypt,
  serializePaillierCiphertextB64u,
  serializePaillierPublicKeyB64u,
} from '@shared/utils/paillier';
import { computeThresholdEd25519RecoveryExportInitChallengeB64u } from '@shared/threshold/ed25519Recovery';

function testWebauthnAuthenticationPayload(): Record<string, unknown> {
  return {
    id: 'test-cred',
    rawId: 'test-cred',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'test',
      authenticatorData: 'test',
      signature: 'test',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

test('threshold-ed25519 export init verifies a bound WebAuthn challenge', async () => {
  const captured: Array<Record<string, unknown>> = [];
  const relayerKeyId = 'ed25519:operational-key';
  const nearAccountId = 'alice.testnet';
  const rpId = 'wallet.example.test';
  const recoveryPublicKey = 'ed25519:recovery-key';
  const keyVersion = 'option-b-v1';

  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey: relayerKeyId,
      recoveryPublicKey,
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async (request) => {
      captured.push(request as unknown as Record<string, unknown>);
      return { success: true, verified: true };
    },
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const result = await schemeAny.export.init({
    relayerKeyId,
    keyVersion,
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });

  expect(result.ok).toBe(true);
  expect(captured).toHaveLength(1);
  expect(captured[0]?.nearAccountId).toBe(nearAccountId);
  expect(captured[0]?.rpId).toBe(rpId);
  expect(captured[0]?.expectedChallenge).toBe(
    await computeThresholdEd25519RecoveryExportInitChallengeB64u({
      nearAccountId,
      rpId,
      relayerKeyId,
      keyVersion,
      recoveryPublicKey,
    }),
  );
});

test('destroyPaillierKeyPair zeroes private key fields', async () => {
  const paillierKeyPair = await generatePaillierKeyPair({ bits: 2048 });
  expect(paillierKeyPair.privateKey.lambda).not.toBe(0n);
  expect(paillierKeyPair.privateKey.mu).not.toBe(0n);

  destroyPaillierKeyPair(paillierKeyPair);

  expect(paillierKeyPair.privateKey.lambda).toBe(0n);
  expect(paillierKeyPair.privateKey.mu).toBe(0n);
});

test('threshold-ed25519 export combine rejects replay after first use', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const nearAccountId = 'alice.testnet';
  const rpId = 'wallet.example.test';
  const recoveryPublicKey = 'ed25519:recovery-key';
  const keyVersion = 'option-b-v1';

  const { svc } = createThresholdSigningServiceForUnitTests({
    config: {
      kind: 'in-memory',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: Buffer.alloc(32, 21).toString('base64url'),
    },
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey: relayerKeyId,
      recoveryPublicKey,
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const init = await schemeAny.export.init({
    relayerKeyId,
    keyVersion,
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });
  expect(init.ok).toBe(true);
  const exportId = String(init.exportId || '');
  expect(exportId).not.toBe('');

  const paillierKeyPair = await generatePaillierKeyPair({ bits: 2048 });
  const paillierPublicKeyB64u = serializePaillierPublicKeyB64u(paillierKeyPair.publicKey);
  const clientCiphertextB64u = serializePaillierCiphertextB64u(
    paillierKeyPair.publicKey,
    paillierEncrypt(paillierKeyPair.publicKey, 17n),
  );

  const first = await schemeAny.export.combine({
    exportId,
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u,
    clientCiphertextB64u,
  });
  expect(first.ok).toBe(true);
  expect(String(first.serverCiphertextB64u || '')).not.toBe('');

  const replay = await schemeAny.export.combine({
    exportId,
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u,
    clientCiphertextB64u,
  });
  expect(replay.ok).toBe(false);
  expect(replay.code).toBe('unauthorized');
  expect(String(replay.message || '')).toContain('expired or invalid');
});

test('threshold-ed25519 export session persistence stores only recovery metadata', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const nearAccountId = 'alice.testnet';
  const rpId = 'wallet.example.test';
  const recoveryPublicKey = 'ed25519:recovery-key';
  const keyVersion = 'option-b-v1';

  const { svc, sessionStore } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey: relayerKeyId,
      recoveryPublicKey,
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const init = await schemeAny.export.init({
    relayerKeyId,
    keyVersion,
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });
  expect(init.ok).toBe(true);

  const persisted = await sessionStore.takeExportSession(String(init.exportId || ''));
  expect(persisted).toMatchObject({
    relayerKeyId,
    nearAccountId,
    rpId,
    recoveryPublicKey,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    participantIds: [1, 2],
  });
  expect((persisted as Record<string, unknown> | null)?.clientCiphertextB64u).toBeUndefined();
  expect((persisted as Record<string, unknown> | null)?.serverCiphertextB64u).toBeUndefined();
  expect((persisted as Record<string, unknown> | null)?.paillierPublicKeyB64u).toBeUndefined();
  expect((persisted as Record<string, unknown> | null)?.recoveryServerShareB64u).toBeUndefined();
  expect((persisted as Record<string, unknown> | null)?.recoveredSeedB64u).toBeUndefined();
});

test('threshold-ed25519 export audit logs never include raw ciphertext or recovery share material', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const nearAccountId = 'alice.testnet';
  const rpId = 'wallet.example.test';
  const recoveryPublicKey = 'ed25519:recovery-key';
  const keyVersion = 'option-b-v1';
  const infoLogs: unknown[][] = [];
  const warnLogs: unknown[][] = [];

  const { svc } = createThresholdSigningServiceForUnitTests({
    config: {
      kind: 'in-memory',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: Buffer.alloc(32, 21).toString('base64url'),
    },
    logger: {
      debug: () => {},
      error: () => {},
      info: (...args: unknown[]) => infoLogs.push(args),
      warn: (...args: unknown[]) => warnLogs.push(args),
    },
    keyRecord: {
      nearAccountId,
      rpId,
      publicKey: relayerKeyId,
      recoveryPublicKey,
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const init = await schemeAny.export.init({
    relayerKeyId,
    keyVersion,
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });
  expect(init.ok).toBe(true);

  const paillierKeyPair = await generatePaillierKeyPair({ bits: 2048 });
  const paillierPublicKeyB64u = serializePaillierPublicKeyB64u(paillierKeyPair.publicKey);
  const clientCiphertextB64u = serializePaillierCiphertextB64u(
    paillierKeyPair.publicKey,
    paillierEncrypt(paillierKeyPair.publicKey, 17n),
  );

  const combine = await schemeAny.export.combine({
    exportId: String(init.exportId || ''),
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u,
    clientCiphertextB64u,
  });
  expect(combine.ok).toBe(true);

  expect(warnLogs).toHaveLength(0);
  const infoPayloads = infoLogs
    .map((entry) => entry[1])
    .filter((entry): entry is Record<string, unknown> => !!entry && typeof entry === 'object');
  expect(infoPayloads.length).toBeGreaterThanOrEqual(2);
  expect(infoPayloads[0]).toMatchObject({
    relayerKeyId,
    nearAccountId,
    rpId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    recoveryPublicKeyConfigured: true,
  });
  expect(infoPayloads[1]).toMatchObject({
    relayerKeyId,
    nearAccountId,
    rpId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    recoveryPublicKeyConfigured: true,
  });

  for (const payload of infoPayloads) {
    expect(payload.clientCiphertextB64u).toBeUndefined();
    expect(payload.serverCiphertextB64u).toBeUndefined();
    expect(payload.paillierPublicKeyB64u).toBeUndefined();
    expect(payload.recoveryServerShareB64u).toBeUndefined();
    expect(payload.recoveredSeedB64u).toBeUndefined();
    expect(payload.recoveryPublicKey).toBeUndefined();
  }

  const serializedLogs = JSON.stringify(infoLogs);
  expect(serializedLogs).not.toContain(clientCiphertextB64u);
  expect(serializedLogs).not.toContain(paillierPublicKeyB64u);
  expect(serializedLogs).not.toContain(String(combine.serverCiphertextB64u || ''));
  expect(serializedLogs).not.toContain(recoveryPublicKey);
});

test('threshold-ed25519 export init rejects the wrong keyVersion', async () => {
  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      publicKey: 'ed25519:operational-key',
      recoveryPublicKey: 'ed25519:recovery-key',
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion: 'option-b-v1',
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const result = await schemeAny.export.init({
    relayerKeyId: 'ed25519:operational-key',
    keyVersion: 'wrong-option-b-v1',
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });

  expect(result.ok).toBe(false);
  expect(result.code).toBe('invalid_body');
  expect(String(result.message || '')).toContain('keyVersion');
});

test('threshold-ed25519 export init requires a persisted recovery public key', async () => {
  let verifyCalls = 0;
  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      publicKey: 'ed25519:operational-key',
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion: 'option-b-v1',
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => {
      verifyCalls += 1;
      return { success: true, verified: true };
    },
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const result = await schemeAny.export.init({
    relayerKeyId: 'ed25519:operational-key',
    keyVersion: 'option-b-v1',
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });

  expect(result.ok).toBe(false);
  expect(result.code).toBe('not_found');
  expect(String(result.message || '')).toContain('Unknown relayerKeyId');
  expect(verifyCalls).toBe(0);
});

test('threshold-ed25519 export init requires persisted recovery export capability', async () => {
  let verifyCalls = 0;
  const { svc } = createThresholdSigningServiceForUnitTests({
    keyRecord: {
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      publicKey: 'ed25519:operational-key',
      recoveryPublicKey: 'ed25519:recovery-key',
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion: 'option-b-v1',
      recoveryExportCapable: false,
    },
    verifyWebAuthnAuthenticationLite: async () => {
      verifyCalls += 1;
      return { success: true, verified: true };
    },
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const result = await schemeAny.export.init({
    relayerKeyId: 'ed25519:operational-key',
    keyVersion: 'option-b-v1',
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });

  expect(result.ok).toBe(false);
  expect(result.code).toBe('not_found');
  expect(String(result.message || '')).toContain('Unknown relayerKeyId');
  expect(verifyCalls).toBe(0);
});

test('threshold-ed25519 export combine rejects an expired ticket', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const keyVersion = 'option-b-v1';
  const { svc, sessionStore } = createThresholdSigningServiceForUnitTests({
    config: {
      kind: 'in-memory',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: Buffer.alloc(32, 21).toString('base64url'),
    },
    keyRecord: {
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      publicKey: relayerKeyId,
      recoveryPublicKey: 'ed25519:recovery-key',
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  await sessionStore.putExportSession(
    'expired-export-ticket',
    {
      expiresAtMs: Date.now() + 1,
      relayerKeyId,
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      recoveryPublicKey: 'ed25519:recovery-key',
      keyVersion,
      artifactKind: 'near-ed25519-option-b-v1',
      participantIds: [1, 2],
    },
    1,
  );
  await new Promise((resolve) => setTimeout(resolve, 10));

  const paillierKeyPair = await generatePaillierKeyPair({ bits: 2048 });
  const paillierPublicKeyB64u = serializePaillierPublicKeyB64u(paillierKeyPair.publicKey);
  const clientCiphertextB64u = serializePaillierCiphertextB64u(
    paillierKeyPair.publicKey,
    paillierEncrypt(paillierKeyPair.publicKey, 17n),
  );

  const expired = await schemeAny.export.combine({
    exportId: 'expired-export-ticket',
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u,
    clientCiphertextB64u,
  });

  expect(expired.ok).toBe(false);
  expect(expired.code).toBe('unauthorized');
  expect(String(expired.message || '')).toContain('expired or invalid');
});

test('threshold-ed25519 export combine uses the authorized export session context', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const keyVersion = 'option-b-v1';
  const sessionRecoveryPublicKey = 'ed25519:session-recovery-key';
  const { svc, sessionStore } = createThresholdSigningServiceForUnitTests({
    config: {
      kind: 'in-memory',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: Buffer.alloc(32, 21).toString('base64url'),
    },
    keyRecord: null,
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  await sessionStore.putExportSession(
    'authorized-export-session',
    {
      expiresAtMs: Date.now() + 60_000,
      relayerKeyId,
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      recoveryPublicKey: sessionRecoveryPublicKey,
      keyVersion,
      artifactKind: 'near-ed25519-option-b-v1',
      participantIds: [1, 2],
    },
    60_000,
  );

  const paillierKeyPair = await generatePaillierKeyPair({ bits: 2048 });
  const paillierPublicKeyB64u = serializePaillierPublicKeyB64u(paillierKeyPair.publicKey);
  const clientCiphertextB64u = serializePaillierCiphertextB64u(
    paillierKeyPair.publicKey,
    paillierEncrypt(paillierKeyPair.publicKey, 17n),
  );

  const result = await schemeAny.export.combine({
    exportId: 'authorized-export-session',
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u,
    clientCiphertextB64u,
  });

  expect(result.ok).toBe(true);
  expect(result.relayerKeyId).toBe(relayerKeyId);
  expect(result.keyVersion).toBe(keyVersion);
  expect(result.recoveryPublicKey).toBe(sessionRecoveryPublicKey);
  expect(result.recoveryExportCapable).toBe(true);
  expect(result.participantIds).toEqual([1, 2]);
  expect(String(result.serverCiphertextB64u || '')).not.toBe('');
});

test('threshold-ed25519 export combine rejects malformed Paillier payloads', async () => {
  const relayerKeyId = 'ed25519:operational-key';
  const keyVersion = 'option-b-v1';
  const { svc } = createThresholdSigningServiceForUnitTests({
    config: {
      kind: 'in-memory',
      THRESHOLD_ED25519_MASTER_SECRET_B64U: Buffer.alloc(32, 21).toString('base64url'),
    },
    keyRecord: {
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      publicKey: relayerKeyId,
      recoveryPublicKey: 'ed25519:recovery-key',
      relayerSigningShareB64u: Buffer.alloc(32, 7).toString('base64url'),
      relayerVerifyingShareB64u: Buffer.alloc(32, 9).toString('base64url'),
      keyVersion,
      recoveryExportCapable: true,
    },
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
  });

  const schemeAny = svc.getSchemeModule('threshold-ed25519-frost-2p-v1');
  if (!schemeAny || schemeAny.schemeId !== 'threshold-ed25519-frost-2p-v1') {
    throw new Error('threshold-ed25519 scheme module is unavailable');
  }

  const init = await schemeAny.export.init({
    relayerKeyId,
    keyVersion,
    webauthn_authentication: testWebauthnAuthenticationPayload() as any,
  });
  expect(init.ok).toBe(true);

  const malformed = await schemeAny.export.combine({
    exportId: String(init.exportId || ''),
    relayerKeyId,
    keyVersion,
    artifactKind: 'near-ed25519-option-b-v1',
    paillierPublicKeyB64u: 'not-a-valid-paillier-public-key',
    clientCiphertextB64u: 'not-a-valid-paillier-ciphertext',
  });

  expect(malformed.ok).toBe(false);
  expect(malformed.code).toBe('invalid_body');
  expect(String(malformed.message || '')).not.toBe('');
});
