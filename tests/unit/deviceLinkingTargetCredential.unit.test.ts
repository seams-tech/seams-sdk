import { expect, test } from '@playwright/test';
import type {
  AuthenticatorOperation,
  AuthenticatorResult,
} from '../../packages/wallet/src/core/platform';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { createDeviceLinkingTargetCredentialPortV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingTargetCredential';
import { toRpId } from '../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildPasskeyTargetPreparationFixtureV1 } from './helpers/linkedDeviceTargetPreparation.fixtures';

function successfulAuthenticatorResult(operation: AuthenticatorOperation): AuthenticatorResult {
  if (operation.kind !== 'create_passkey' || !operation.requirePrfFirst) {
    throw new Error('test requires a PRF-backed passkey creation operation');
  }
  return {
    ok: true,
    operation: 'create_passkey',
    requirePrfFirst: true,
    credential: {
      id: 'target-credential',
      rawId: 'dGFyZ2V0LWNyZWRlbnRpYWw',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'client-data',
        attestationObject: 'attestation-object',
        transports: ['internal'],
      },
      clientExtensionResults: {
        prf: { results: { first: undefined, second: undefined } },
      },
    },
    credentialIdB64u: 'dGFyZ2V0LWNyZWRlbnRpYWw',
    rawIdB64u: 'dGFyZ2V0LWNyZWRlbnRpYWw',
    rpId: toRpId(operation.registrationOptions.rpId),
    prf: {
      kind: 'required',
      prfFirstB64u: base64UrlEncode(new Uint8Array(32)),
    },
  };
}

test('target passkey creation uses the server-bound ceremony options', async () => {
  const preparation = buildPasskeyTargetPreparationFixtureV1();
  let observedOperation: AuthenticatorOperation | null = null;
  const targetCredential = createDeviceLinkingTargetCredentialPortV1({
    authenticator: {
      kind: 'authenticator',
      async run(operation) {
        observedOperation = operation;
        return successfulAuthenticatorResult(operation);
      },
    },
  });

  const result = await targetCredential.createTargetCredentialV1({
    preparation,
    keyMaterial: {
      kind: 'device_linking_key_material_handle_v1',
      handleId: 'test-handle',
    },
  });

  expect(observedOperation).toEqual({
    kind: 'create_passkey',
    registrationOptions: preparation.passkeyCreationOptions,
    requirePrfFirst: true,
  });
  expect(result.walletAuthMethodId).toBe(preparation.walletAuthMethodId);
  expect(result.factorSecret).toHaveLength(32);
  expect(result.webauthnRegistration.credentialIdB64u).toBe('dGFyZ2V0LWNyZWRlbnRpYWw');
});
