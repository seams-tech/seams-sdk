import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { createLinkedDeviceLocalPresencePortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/linkedDeviceLocalPresence';
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
  const port = createLinkedDeviceLocalPresencePortV1({
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
  });
  const authorizedOperationId = requiredAuthorizedOperationId(
    'linked-ed25519-authorized-operation:request-1',
  );
  const intentDigestB64u = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));
  const result = await port.authorizeAndOpenHolderV1({
    bundle,
    child,
    authorizedOperationId,
    intentDigestB64u,
    issuedAtMs: bundle.issuedAtMs,
    expiresAtMs: bundle.issuedAtMs + 30_000,
  });
  expect(openedFactor).toEqual(new Uint8Array(32).fill(7));
  expect(result.localPresenceAssertion.challengeDigestB64u).toBe(requestedChallengeB64u);
  expect(result.localPresenceAssertion.assertion.clientExtensionResults).toBeNull();
  expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
  expect(result.holderMaterial).toMatchObject({
    kind: 'device_linking_holder_signing_material_handle_v1',
    keyFamily: child.keyFamily,
  });
});
