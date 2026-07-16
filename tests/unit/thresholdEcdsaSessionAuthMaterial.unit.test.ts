import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/_test-sdk/esm/core/signingEngine/session/persistence/records.js',
  warmSessionCapabilityReader:
    '/_test-sdk/esm/core/signingEngine/session/warmCapabilities/capabilityReader.js',
  routerAbEcdsaWalletSessionAuth:
    '/_test-sdk/esm/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth.js',
  ecdsaRoleLocalRecords:
    '/_test-sdk/esm/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.js',
} as const;

test.describe('threshold ECDSA warm-session auth material', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

test('resolves JWT only from explicit canonical ECDSA ownership', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const storeMod = await import(paths.thresholdSessionStore);
        const capabilityReaderMod = await import(paths.warmSessionCapabilityReader);
        const routerAbEcdsaWalletSessionAuthMod = await import(
          paths.routerAbEcdsaWalletSessionAuth
        );
        const ecdsaRoleLocalMod = await import(paths.ecdsaRoleLocalRecords);
        const deps = {
          recordsByLane: new Map<string, unknown>(),
          exportArtifactsByLane: new Map<string, unknown>(),
        };
        const now = Date.now();

        const upsertEcdsaRecord = (args: {
          walletId: string;
          thresholdSessionId: string;
          thresholdSessionKind: 'jwt' | 'cookie';
          walletSessionJwt?: string;
        }) => {
          const chainTarget = {
            kind: 'tempo',
            chainId: 42431,
            networkSlug: 'tempo-42431',
          };
          const signingGrantId = `wallet-${args.thresholdSessionId}`;
          const ecdsaThresholdKeyId = `ek-${args.walletId}`;
          const keyHandle = `key-handle-${args.thresholdSessionId}`;
          const signingRootId = 'proj-a:env-a';
          const signingRootVersion = 'default';
          const evmFamilySigningKeySlotId = `wallet-key:evm-family:${encodeURIComponent(
            args.walletId,
          )}:${encodeURIComponent(signingRootId)}:${encodeURIComponent(signingRootVersion)}`;
          const ecdsaRoleLocalReadyRecord = ecdsaRoleLocalMod.buildEcdsaRoleLocalReadyRecord({
            stateBlob: {
              kind: 'ecdsa_role_local_state_blob_v1',
              curve: 'secp256k1',
              encoding: 'base64url',
              producer: 'signer_core',
              stateBlobB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
            publicFacts: ecdsaRoleLocalMod.buildEcdsaRoleLocalPublicFacts({
              walletId: args.walletId,
              evmFamilySigningKeySlotId,
              chainTarget,
              keyHandle,
              ecdsaThresholdKeyId,
              signingRootId,
              signingRootVersion,
              clientParticipantId: 1,
              relayerParticipantId: 2,
              participantIds: [1, 2],
              applicationBindingDigestB64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
              contextBinding32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              derivationClientSharePublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              relayerPublicKey33B64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              groupPublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              ethereumAddress: `0x${'11'.repeat(20)}`,
            }),
            authMethod: ecdsaRoleLocalMod.buildEcdsaRoleLocalPasskeyAuthMethod({
              credentialIdB64u: `credential-${args.thresholdSessionId}`,
              rpId: 'example.localhost',
            }),
          });
          storeMod.upsertRestoredThresholdEcdsaSessionRecord({
            walletId: args.walletId,
            evmFamilySigningKeySlotId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            chainTarget,
            keyHandle,
            ecdsaThresholdKeyId,
            signingRootId,
            signingRootVersion,
            relayerKeyId: `rk-${args.thresholdSessionId}`,
            clientVerifyingShareB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ecdsaRoleLocalReadyRecord,
            participantIds: [1, 2],
            thresholdSessionKind: args.thresholdSessionKind,
            thresholdSessionId: args.thresholdSessionId,
            signingGrantId,
            ...(args.walletSessionJwt
              ? { walletSessionJwt: args.walletSessionJwt }
              : {}),
            expiresAtMs: now + 120_000,
            remainingUses: 9,
            thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ethereumAddress: `0x${'11'.repeat(20)}`,
            updatedAtMs: now,
            source: 'login',
          });
        };

        storeMod.clearAllStoredThresholdEd25519SessionRecords();
        storeMod.clearAllThresholdEcdsaSessionRecords(deps);

        upsertEcdsaRecord({
          walletId: 'primary.testnet',
          thresholdSessionId: 'sess-ecdsa-jwt',
          thresholdSessionKind: 'jwt',
          walletSessionJwt: 'jwt-ecdsa-primary',
        });

        const capabilityReader = capabilityReaderMod.createWarmSessionCapabilityReader();
        const resolvedPrimary =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId('sess-ecdsa-jwt');
        const resolvedMissing =
          capabilityReader.resolveEcdsaAuthByThresholdSessionId('sess-missing');
        const persistedRecord = storeMod.getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
          'sess-ecdsa-jwt',
        );
        const staleRecordWithoutJwt = persistedRecord
          ? {
              ...persistedRecord,
              walletSessionJwt: undefined,
            }
          : null;
        const staleRecordResolution = staleRecordWithoutJwt
          ? routerAbEcdsaWalletSessionAuthMod.resolveRouterAbEcdsaWalletSessionAuthFromRecord(
              staleRecordWithoutJwt,
            )
          : null;

        return {
          primary: resolvedPrimary
            ? {
                source: resolvedPrimary.walletSessionJwtSource,
                jwt: resolvedPrimary.walletSessionJwt || null,
              }
            : null,
          missing: resolvedMissing,
          staleRecordResolution,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.primary).toEqual({
      source: 'ecdsa_record',
      jwt: 'jwt-ecdsa-primary',
    });
    expect(result.missing).toBeNull();
    expect(result.staleRecordResolution).toEqual({
      kind: 'unavailable',
      reason: 'missing_wallet_session_jwt',
    });
  });
});
