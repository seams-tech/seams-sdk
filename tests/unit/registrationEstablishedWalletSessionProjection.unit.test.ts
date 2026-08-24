import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

const INDEXED_DB_PATH = '/_test-sdk/esm/core/indexedDB/index.js';
const PROJECTION_PATH =
  '/_test-sdk/esm/core/signingEngine/session/persistence/walletSessionAuthorizationProjection.js';

test.describe('registration-established Wallet Session projection', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('creates Ed25519 authorization and merges it after ECDSA registration without mutation on mismatch', async ({
    page,
  }) => {
    const invalidBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'registration-invalid-restore-wallet',
      chain: 'evm',
    });
    const invalidRestoreBootstrap = {
      ...invalidBootstrap,
      session: {
        ...invalidBootstrap.session,
        walletSessionToken: '',
      },
    };
    const result = await page.evaluate(
      async ({ indexedDbPath, projectionPath, invalidRestoreBootstrap }) => {
        const {
          createSeamsTestWalletDbName,
          SeamsWalletDBManager,
          WalletSessionAuthorizationRepository,
        } = await import(indexedDbPath);
        const {
          persistActiveWalletSessionAuthorizationFromEcdsaBootstrap,
          persistActiveWalletSessionAuthorizationFromRegistration,
        } = await import(projectionPath);

        const walletSessionToken = (
          identity: {
            walletId: string;
            seamsSessionId: string;
            authorizationId: string;
            walletSessionId: string;
            quotaId: string;
            expiresAtMs: number;
          },
          iat?: number,
        ): string => {
          return `wst:registration:${identity.walletId}:${iat ?? 'initial'}`;
        };
        const identity = (walletId: string) => ({
          walletId,
          seamsSessionId: `registration-seams:${walletId}`,
          authorizationId: `registration-authorization:${walletId}`,
          walletSessionId: `registration-wallet-session:${walletId}`,
          quotaId: `registration-quota:${walletId}`,
          expiresAtMs: 2_000_000_000_000,
        });
        const passkeyAuthority = (walletId: string, authorityDigest: string) => ({
          kind: 'wallet_auth_authority_ref',
          walletId,
          authorityDigest,
          walletAuthMethodId: `passkey:${walletId}:fixture`,
        });
        const ecdsaRegistrationSession = (
          sessionIdentity: ReturnType<typeof identity>,
          iat?: number,
        ) => ({
          kind: 'registration_established_wallet_session_v1',
          ...sessionIdentity,
          remainingUses: 3,
          tokens: {
            kind: 'evm_family_ecdsa',
            ecdsa: {
              sessionKind: 'opaque',
              walletSessionToken: walletSessionToken(sessionIdentity, iat),
              thresholdSessionId: sessionIdentity.seamsSessionId,
            },
          },
        });
        const ed25519RegistrationSession = (sessionIdentity: ReturnType<typeof identity>) => ({
          kind: 'registration_established_wallet_session_v1',
          ...sessionIdentity,
          remainingUses: 3,
          tokens: {
            kind: 'near_ed25519',
            ed25519: {
              sessionKind: 'opaque',
              walletSessionToken: walletSessionToken(sessionIdentity),
              thresholdSessionId: sessionIdentity.seamsSessionId,
            },
          },
        });

        const manager = new SeamsWalletDBManager();
        manager.setDbName(
          createSeamsTestWalletDbName(`registration-projection-${crypto.randomUUID()}`),
        );
        const repository = new WalletSessionAuthorizationRepository(manager);
        try {
          const mixedIdentity = identity('registration-mixed-projection-wallet');
          const ecdsaIdentity = {
            ...mixedIdentity,
            expiresAtMs: mixedIdentity.expiresAtMs + 1,
          };
          const authority = passkeyAuthority(mixedIdentity.walletId, 'AQ');
          await persistActiveWalletSessionAuthorizationFromRegistration(repository, {
            authority,
            authMethod: 'passkey',
            session: ecdsaRegistrationSession(ecdsaIdentity, 1),
          });
          await persistActiveWalletSessionAuthorizationFromRegistration(repository, {
            authority,
            authMethod: 'passkey',
            session: ed25519RegistrationSession(mixedIdentity),
          });
          const merged = await repository.readActiveForWallet(mixedIdentity.walletId);
          const mergedKind =
            merged.kind === 'found' ? merged.projection.walletSessionTokens.kind : 'missing';
          const mergedExpiresAtMs = merged.kind === 'found' ? merged.projection.expiresAtMs : null;
          const mergedTokens =
            merged.kind === 'found' &&
            merged.projection.walletSessionTokens.kind === 'near_ed25519_and_evm_family_ecdsa'
              ? {
                  ed25519: merged.projection.walletSessionTokens.ed25519.walletSessionToken,
                  ecdsa: merged.projection.walletSessionTokens.ecdsa.walletSessionToken,
                }
              : null;
          const mergedTokenPresence = mergedTokens
            ? { ed25519: Boolean(mergedTokens.ed25519), ecdsa: Boolean(mergedTokens.ecdsa) }
            : null;

          await persistActiveWalletSessionAuthorizationFromRegistration(repository, {
            authority,
            authMethod: 'passkey',
            session: ecdsaRegistrationSession(ecdsaIdentity, 2),
          });
          const reissued = await repository.readActiveForWallet(mixedIdentity.walletId);
          const reissuedTokens =
            reissued.kind === 'found' &&
            reissued.projection.walletSessionTokens.kind === 'near_ed25519_and_evm_family_ecdsa'
              ? {
                  ed25519: reissued.projection.walletSessionTokens.ed25519.walletSessionToken,
                  ecdsa: reissued.projection.walletSessionTokens.ecdsa.walletSessionToken,
                }
              : null;
          const reissuedTokenState =
            mergedTokens && reissuedTokens
              ? {
                  ecdsaReplaced: reissuedTokens.ecdsa !== mergedTokens.ecdsa,
                  ed25519Retained: reissuedTokens.ed25519 === mergedTokens.ed25519,
                }
              : null;

          let mismatchMessage = '';
          try {
            await persistActiveWalletSessionAuthorizationFromRegistration(repository, {
              authority: passkeyAuthority(mixedIdentity.walletId, 'Ag'),
              authMethod: 'passkey',
              session: ed25519RegistrationSession(mixedIdentity),
            });
          } catch (error: unknown) {
            mismatchMessage = error instanceof Error ? error.message : String(error);
          }
          const afterMismatch = await repository.readActiveForWallet(mixedIdentity.walletId);
          const afterMismatchKind =
            afterMismatch.kind === 'found'
              ? afterMismatch.projection.walletSessionTokens.kind
              : 'missing';

          const edOnlyIdentity = identity('registration-ed-only-projection-wallet');
          await persistActiveWalletSessionAuthorizationFromRegistration(repository, {
            authority: passkeyAuthority(edOnlyIdentity.walletId, 'Aw'),
            authMethod: 'passkey',
            session: ed25519RegistrationSession(edOnlyIdentity),
          });
          const edOnly = await repository.readActiveForWallet(edOnlyIdentity.walletId);
          const edOnlyKind =
            edOnly.kind === 'found' ? edOnly.projection.walletSessionTokens.kind : 'missing';

          let invalidRestoreMessage = '';
          try {
            await persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(repository, {
              walletId: 'registration-invalid-restore-wallet',
              authority: passkeyAuthority('registration-invalid-restore-wallet', 'Aw'),
              authMethod: 'passkey',
              bootstrap: invalidRestoreBootstrap,
            });
          } catch (error: unknown) {
            invalidRestoreMessage = error instanceof Error ? error.message : String(error);
          }
          const afterInvalidRestore = await repository.readActiveForWallet(
            'registration-invalid-restore-wallet',
          );
          return {
            mergedKind,
            mergedExpiresAtMs,
            mergedTokenPresence,
            reissuedTokenState,
            mismatchMessage,
            afterMismatchKind,
            edOnlyKind,
            invalidRestoreMessage,
            invalidRestoreProjection: afterInvalidRestore.kind,
          };
        } finally {
          manager.close();
        }
      },
      {
        indexedDbPath: INDEXED_DB_PATH,
        projectionPath: PROJECTION_PATH,
        invalidRestoreBootstrap,
      },
    );

    expect(result).toEqual({
      mergedKind: 'near_ed25519_and_evm_family_ecdsa',
      mergedExpiresAtMs: 2_000_000_000_000,
      mergedTokenPresence: { ed25519: true, ecdsa: true },
      reissuedTokenState: { ecdsaReplaced: true, ed25519Retained: true },
      mismatchMessage: 'Wallet Session authorization identity does not match the active projection',
      afterMismatchKind: 'near_ed25519_and_evm_family_ecdsa',
      edOnlyKind: 'near_ed25519',
      invalidRestoreMessage: 'walletSessionToken is required',
      invalidRestoreProjection: 'missing',
    });
  });
});
