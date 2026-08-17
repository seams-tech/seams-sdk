import { expect, test } from '@playwright/test';
import { CloudflareD1WalletAuthMethodService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';

/**
 * Finalize consumes its ceremony, so a client that never saw the response has
 * nothing left to ask with: the ceremony is gone and the credential is already
 * registered. Without a replay record the only available answer is `not_found`,
 * which tells the client to start over when it cannot.
 *
 * These own the two halves of that — the retry has to be answered from the
 * stored response, and anything that is not the same finalize has to be refused
 * rather than handed someone else's success.
 */
const WALLET_ID = walletIdFromString('replay-wallet.testnet');
const RP_ID = parseWebAuthnRpId('wallet.example.test');
if (!RP_ID.ok) throw new Error(RP_ID.error.message);
const CEREMONY_ID = 'add-auth-method-ceremony:replay';

function storedResponse() {
  return {
    ok: true as const,
    walletId: WALLET_ID,
    authority: buildPasskeyWalletAuthAuthority({
      walletId: WALLET_ID,
      rpId: RP_ID.value,
      credentialIdB64u: 'credential-original',
    }),
    rpId: RP_ID.value,
    authMethod: {
      kind: 'passkey' as const,
      status: 'active' as const,
      credentialIdB64u: 'credential-original',
      credentialPublicKeyB64u: 'public-key-original',
      counter: 0,
      device: unknownWebAuthnAuthenticatorDeviceInfo(),
    },
  };
}

function finalizeCommand(overrides: Record<string, unknown> = {}) {
  return {
    subject: { kind: 'wallet_auth_method_management' as const, walletId: WALLET_ID },
    addAuthMethodCeremonyId: CEREMONY_ID,
    webauthnRegistration: { id: 'credential-original', response: { attestation: 'a' } },
    custodyEnvelope: { kind: 'passkey_custody_envelope_v1', nonceB64u: 'nonce-original' },
    authorization: { kind: 'owner' as const },
    ...overrides,
  };
}

/**
 * A store in the state a retry arrives in: the ceremony consumed, the replay
 * record present. `requestDigestB64u` is whatever the service itself computed
 * for the original command, so the test never restates the digest rule.
 */
function serviceWithStoredFinalize(requestDigestB64u: string) {
  return new CloudflareD1WalletAuthMethodService({
    getRegistrationCeremonyIntentStore: () => ({
      getAddAuthMethodFinalizeReplay: async (id: string) =>
        id === CEREMONY_ID
          ? {
              kind: 'wallet_add_auth_method_finalize_replay_v1' as const,
              addAuthMethodCeremonyId: CEREMONY_ID,
              requestDigestB64u,
              response: storedResponse(),
              createdAtMs: 1_800_000_000_000,
              expiresAtMs: 1_900_000_000_000,
            }
          : null,
      getAddAuthMethodCeremony: async () => null,
    }),
    sha256Bytes,
  } as never);
}

function replayDigestOf(command: unknown): Promise<string> {
  return (
    serviceWithStoredFinalize('') as unknown as {
      finalizeReplayDigestB64u(input: unknown): Promise<string>;
    }
  ).finalizeReplayDigestB64u(command);
}

test('an exact retry after ceremony consumption returns the original response', async () => {
  const command = finalizeCommand();
  const service = serviceWithStoredFinalize(await replayDigestOf(command));
  expect(await service.finalizeWalletAddAuthMethod(command as never)).toEqual(storedResponse());
});

test('a substituted credential, envelope, or admitted identity is refused', async () => {
  const original = finalizeCommand();
  const service = serviceWithStoredFinalize(await replayDigestOf(original));
  // Each of these is a different finalize wearing the same ceremony id.
  const substitutions = [
    { webauthnRegistration: { id: 'credential-substituted', response: { attestation: 'a' } } },
    { custodyEnvelope: { kind: 'passkey_custody_envelope_v1', nonceB64u: 'nonce-substituted' } },
    {
      authorization: {
        kind: 'linked_device' as const,
        tenantId: 'tenant-substituted',
        admission: {
          walletId: WALLET_ID,
          enrollmentId: 'enrollment-substituted',
          deviceId: 'device-substituted',
          keyManifestDigestB64u: 'manifest-substituted',
          addAuthMethodCeremonyId: CEREMONY_ID,
        },
      },
    },
  ];
  for (const substitution of substitutions) {
    expect(
      await service.finalizeWalletAddAuthMethod(finalizeCommand(substitution) as never),
    ).toMatchObject({
      ok: false,
      code: 'conflict',
      message: 'add-auth-method ceremony was already finalized with a different request',
    });
  }
  // The unmodified command still replays, so the refusals above are about the
  // substitution and not a store that refuses everything.
  expect(await service.finalizeWalletAddAuthMethod(original as never)).toEqual(storedResponse());
});
