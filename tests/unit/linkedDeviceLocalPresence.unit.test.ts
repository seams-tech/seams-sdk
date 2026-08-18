import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/wallet/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { authorizeAndOpenLinkedDeviceHolderV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/linkedDeviceLocalPresence';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR103SealedHolderRecord } from './helpers/r102LaneGateway.fixtures';

function requiredAuthorizedOperationId(value: string) {
  const parsed = parseAuthorizedOperationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

test('binds one WebAuthn assertion and PRF-opened holder to the active linked child', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const bundle = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
    walletSessionDelivery: fixture.walletSession,
  });
  const child = bundle.orderedExecutions[0];
  const credentialIdB64u =
    bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  const holderRecord = buildR103SealedHolderRecord(child.job, child.protocolCommitReceipt);
  let requestedChallengeB64u = '';
  let openedFactor = new Uint8Array();
  const events: string[] = [];
  const dependencies = {
    authenticator: {
      kind: 'authenticator',
      async run(operation) {
        if (operation.kind !== 'get_passkey' || operation.requirePrfFirst !== true) {
          throw new Error('linked presence test requires a PRF-backed authentication');
        }
        requestedChallengeB64u = operation.challengeB64u;
        return {
          ok: true,
          operation: 'get_passkey',
          requirePrfFirst: true,
          credential: {
            id: credentialIdB64u,
            rawId: credentialIdB64u,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: base64UrlEncode(new Uint8Array([1])),
              authenticatorData: base64UrlEncode(new Uint8Array([2])),
              signature: base64UrlEncode(new Uint8Array(64).fill(3)),
              userHandle: undefined,
            },
            clientExtensionResults: {
              prf: {
                enabled: true,
                results: { first: base64UrlEncode(new Uint8Array(32).fill(7)) },
              },
            },
          },
          credentialIdB64u,
          rawIdB64u: credentialIdB64u,
          rpId: operation.rpId,
          prf: {
            kind: 'required',
            prfFirstB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
          },
        };
      },
    },
    holderRepository: {
      async put() {},
      async get() {
        return holderRecord;
      },
      async listForEnrollmentV1() {
        return [holderRecord];
      },
      async delete() {},
    },
    holderMaterial: {
      async openPersistedHolderSigningMaterialV1(input) {
        events.push('holder-open');
        openedFactor = new Uint8Array(input.factorSecret).slice();
        return {
          kind: 'device_linking_holder_signing_material_handle_v1',
          handleId: 'holder-material-1',
          keyFamily: child.keyFamily,
        };
      },
      async createEd25519HolderSigningShareV1() {
        throw new Error('signing is outside the local-presence test');
      },
      async discardHolderSigningMaterialV1() {},
    },
  };
  const authorizedOperationId = requiredAuthorizedOperationId(
    'linked-ed25519-authorized-operation:request-1',
  );
  const intentDigestB64u = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));
  const result = await authorizeAndOpenLinkedDeviceHolderV1({
    ...dependencies,
    bundle,
    child,
    authorizedOperationId,
    intentDigestB64u,
    issuedAtMs: bundle.issuedAtMs,
    expiresAtMs: bundle.issuedAtMs + 30_000,
    authorizeBeforeOpen: async () => {
      events.push('gateway-init-claim');
      return { kind: 'authorized' as const };
    },
  });
  expect(events).toEqual(['gateway-init-claim', 'holder-open']);
  expect(result.authorizationResult).toEqual({ kind: 'authorized' });
  expect(openedFactor).toEqual(new Uint8Array(32).fill(7));
  expect(result.localPresenceAssertion.challengeDigestB64u).toBe(requestedChallengeB64u);
  expect(result.localPresenceAssertion.assertion.clientExtensionResults).toBeNull();
  expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
  expect(result.holderMaterial).toMatchObject({
    kind: 'device_linking_holder_signing_material_handle_v1',
    keyFamily: child.keyFamily,
  });
});

test('zeroizes PRF before holder open when the Gateway claim fails', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const bundle = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
    walletSessionDelivery: fixture.walletSession,
  });
  const child = bundle.orderedExecutions[0];
  const credentialIdB64u =
    bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  const holderRecord = buildR103SealedHolderRecord(child.job, child.protocolCommitReceipt);
  let holderOpened = false;
  const authenticator = {
    kind: 'authenticator' as const,
    async run(operation: { readonly kind: 'get_passkey'; readonly rpId: string }) {
      const prfFirstB64u = base64UrlEncode(new Uint8Array(32).fill(7));
      return {
        ok: true as const,
        operation: 'get_passkey' as const,
        requirePrfFirst: true as const,
        credential: {
          id: credentialIdB64u,
          rawId: credentialIdB64u,
          type: 'public-key' as const,
          authenticatorAttachment: 'platform' as const,
          response: {
            clientDataJSON: 'AQ',
            authenticatorData: 'Ag',
            signature: base64UrlEncode(new Uint8Array(64).fill(3)),
            userHandle: undefined,
          },
          clientExtensionResults: {
            prf: { enabled: true, results: { first: prfFirstB64u } },
          },
        },
        credentialIdB64u,
        rawIdB64u: credentialIdB64u,
        rpId: operation.rpId,
        prf: { kind: 'required' as const, prfFirstB64u },
      };
    },
  };
  await expect(
    authorizeAndOpenLinkedDeviceHolderV1({
      authenticator,
      holderRepository: {
        async get() {
          return holderRecord;
        },
        async put() {},
        async listForEnrollmentV1() {
          return [holderRecord];
        },
        async delete() {},
      },
      holderMaterial: {
        async openPersistedHolderSigningMaterialV1() {
          holderOpened = true;
          throw new Error('holder must remain closed');
        },
        async createEd25519HolderSigningShareV1() {
          throw new Error('holder must remain closed');
        },
        async discardHolderSigningMaterialV1() {},
      },
      bundle,
      child,
      authorizedOperationId: requiredAuthorizedOperationId(
        'linked-ed25519-authorized-operation:claim-failure',
      ),
      intentDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
      issuedAtMs: bundle.issuedAtMs,
      expiresAtMs: bundle.issuedAtMs + 30_000,
      authorizeBeforeOpen: async () => {
        throw new Error('Gateway claim failed');
      },
    }),
  ).rejects.toThrow('Gateway claim failed');
  expect(holderOpened).toBe(false);
});
