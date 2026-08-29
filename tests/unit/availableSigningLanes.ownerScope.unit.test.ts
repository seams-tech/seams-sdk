import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

const AVAILABLE_SIGNING_LANES_PATH =
  '/_test-sdk/esm/core/signingEngine/session/availability/availableSigningLanes.js';

const WALLET_ID = 'owner-scope-wallet';

/**
 * R103C Phase 2 proof: an owner-scoped read selects only the exact owner's
 * lanes, and neither sibling owner rows nor retired rows change its result.
 */
test.describe('owner-scoped available signing lanes', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('sibling owner rows never reach the scoped result and cannot change it', async ({
    page,
  }) => {
    const ownerA = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-a-session',
      credentialIdB64u: 'credential-owner-a',
      signerSlot: 1,
    });
    const ownerB = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-b-session',
      credentialIdB64u: 'credential-owner-b',
      signerSlot: 2,
    });
    const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(ownerA);
    const result = await page.evaluate(
      async ({ modulePath, ownerA, ownerB, authorization }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const scopeA = {
          auth: {
            kind: 'passkey',
            rpId: ownerA.ed25519Restore.rpId,
            credentialIdB64u: ownerA.ed25519Restore.credentialIdB64u,
          },
          signerSlot: ownerA.ed25519Restore.signerSlot,
        };
        const read = async (records: unknown[]) =>
          await readAvailableSigningLanes(
            {
              walletId: ownerA.walletId,
              ecdsaChainTargets: [],
              authMethod: 'passkey',
              ownerScope: scopeA,
            },
            {
              listSealedRecordsForWallet: async () => records,
              readActiveWalletSessionAuthorization: async () => ({
                kind: 'found',
                authorization,
              }),
            },
          );
        const withSibling = await read([ownerA, ownerB]);
        const withoutSibling = await read([ownerA]);
        const summarize = (lanes: {
          candidates: { ed25519: { near: readonly { auth: { credentialIdB64u?: string } }[] } };
          lanes: { ed25519: { near: { state: string; auth?: { credentialIdB64u?: string } } } };
        }) => ({
          candidateCredentials: lanes.candidates.ed25519.near.map(
            (lane) => lane.auth.credentialIdB64u,
          ),
          aggregateState: lanes.lanes.ed25519.near.state,
          aggregateCredential: lanes.lanes.ed25519.near.auth?.credentialIdB64u ?? null,
        });
        return {
          withSibling: summarize(withSibling),
          withoutSibling: summarize(withoutSibling),
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        ownerA,
        ownerB,
        authorization,
      },
    );

    expect(result.withSibling.candidateCredentials).toEqual(['credential-owner-a']);
    expect(result.withSibling.aggregateCredential).toBe('credential-owner-a');
    expect(result.withSibling).toEqual(result.withoutSibling);
  });

  test('retired rows for the same owner do not change the scoped result', async ({ page }) => {
    const current = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-a-current-session',
      credentialIdB64u: 'credential-owner-a',
      signerSlot: 1,
      expiresAtMs: Date.now() + 3_600_000,
    });
    const retired = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-a-retired-session',
      credentialIdB64u: 'credential-owner-a',
      signerSlot: 1,
      expiresAtMs: 1_000,
    });
    const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(current);
    const result = await page.evaluate(
      async ({ modulePath, current, retired, authorization }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const scope = {
          auth: {
            kind: 'passkey',
            rpId: current.ed25519Restore.rpId,
            credentialIdB64u: current.ed25519Restore.credentialIdB64u,
          },
          signerSlot: current.ed25519Restore.signerSlot,
        };
        const read = async (records: unknown[]) =>
          await readAvailableSigningLanes(
            {
              walletId: current.walletId,
              ecdsaChainTargets: [],
              authMethod: 'passkey',
              ownerScope: scope,
            },
            {
              listSealedRecordsForWallet: async () => records,
              readActiveWalletSessionAuthorization: async () => ({
                kind: 'found',
                authorization,
              }),
            },
          );
        const withRetired = await read([retired, current]);
        const withoutRetired = await read([current]);
        const aggregate = (lanes: {
          lanes: {
            ed25519: {
              near: { state: string; thresholdSessionId?: string };
            };
          };
        }) => ({
          state: lanes.lanes.ed25519.near.state,
          thresholdSessionId: lanes.lanes.ed25519.near.thresholdSessionId ?? null,
        });
        return {
          withRetired: aggregate(withRetired),
          withoutRetired: aggregate(withoutRetired),
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        current,
        retired,
        authorization,
      },
    );

    expect(result.withRetired.thresholdSessionId).toBe('owner-a-current-session');
    expect(result.withRetired).toEqual(result.withoutRetired);
  });

  test('a scoped read for the sibling owner selects only that owner', async ({ page }) => {
    const ownerA = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-a-session',
      credentialIdB64u: 'credential-owner-a',
      signerSlot: 1,
    });
    const ownerB = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: WALLET_ID,
      thresholdSessionId: 'owner-b-session',
      credentialIdB64u: 'credential-owner-b',
      signerSlot: 2,
    });
    const authorizationB = buildPasskeyEd25519AuthorizationProjectionFixture(ownerB);
    const result = await page.evaluate(
      async ({ modulePath, ownerA, ownerB, authorizationB }) => {
        const { readAvailableSigningLanes } = await import(modulePath);
        const lanes = await readAvailableSigningLanes(
          {
            walletId: ownerB.walletId,
            ecdsaChainTargets: [],
            authMethod: 'passkey',
            ownerScope: {
              auth: {
                kind: 'passkey',
                rpId: ownerB.ed25519Restore.rpId,
                credentialIdB64u: ownerB.ed25519Restore.credentialIdB64u,
              },
              signerSlot: ownerB.ed25519Restore.signerSlot,
            },
          },
          {
            listSealedRecordsForWallet: async () => [ownerA, ownerB],
            readActiveWalletSessionAuthorization: async () => ({
              kind: 'found',
              authorization: authorizationB,
            }),
          },
        );
        return {
          candidateCredentials: lanes.candidates.ed25519.near.map(
            (lane: { auth: { credentialIdB64u?: string } }) => lane.auth.credentialIdB64u,
          ),
        };
      },
      {
        modulePath: AVAILABLE_SIGNING_LANES_PATH,
        ownerA,
        ownerB,
        authorizationB,
      },
    );

    expect(result.candidateCredentials).toEqual(['credential-owner-b']);
  });
});
