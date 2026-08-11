import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseLinkedDeviceTargetPreparationV1 } from '../../packages/shared-ts/src/device-linking';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/device-linking-key.worker';
import { createDeviceLinkingTargetCredentialPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingTargetCredential';
import { toRpId } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { AuthenticatorPort } from '../../packages/sdk-web/src/core/platform';
import type { DeviceLinkingKeyMaterialPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingPorts';

class FakeWorkerScope {
  readonly responses: unknown[] = [];
  private listener: ((event: MessageEvent) => void) | null = null;

  postMessage(message: unknown): void {
    this.responses.push(message);
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listener = listener;
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    if (this.listener === listener) this.listener = null;
  }

  send(message: unknown): void {
    this.listener?.({ data: message } as MessageEvent);
  }
}

function digest(seed: number): string {
  return base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => seed + index));
}

function challenge(): string {
  return base64UrlEncode(new Uint8Array(32).fill(7));
}

function targetPreparation() {
  return parseLinkedDeviceTargetPreparationV1({
    kind: 'linked_device_target_preparation_v1',
    linkSessionId: 'link-session-1',
    walletId: 'wallet-1',
    enrollmentId: 'linked-enrollment-1',
    deviceId: 'linked-device-1',
    rpId: 'wallet.example.test',
    userHandleB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    challengeB64u: digest(5),
    orderedChildren: [
      {
        kind: 'linked_device_target_preparation_child_v1',
        operationId: 'lane-operation-1',
        walletKeyId: 'wallet-key-1',
        keyFamily: 'ed25519',
        targetLaneId: 'linked-lane-1',
        targetLaneShareEpoch: '1',
        targetMaterialActivationId: 'material-activation-1',
        targetHolderParticipantId: 'holder-participant-1',
      },
    ],
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
  });
}

async function waitForResponse(scope: FakeWorkerScope): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = scope.responses.at(0);
    if (response && typeof response === 'object') return response as Record<string, unknown>;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('worker response timed out');
}

test.describe('device-linking key worker', () => {
  test('keeps key material in the worker and signs the canonical request bytes', async () => {
    const scope = new FakeWorkerScope();
    let recipientsDestroyed = 0;
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      createRecipient() {
        return {
          hpke_public_key_b64u: () => digest(21),
          hpke_public_key_digest_b64u: () => digest(31),
          destroy: () => {
            recipientsDestroyed += 1;
          },
          free: () => undefined,
        };
      },
    });
    scope.send({ id: 'create', request: { kind: 'device_linking_key_material_create_v1' } });
    const created = await waitForResponse(scope);
    expect(created.ok).toBe(true);
    const result = created.result as Record<string, unknown>;
    expect(Object.keys(result).sort()).toEqual([
      'devicePublicKeyB64u',
      'handleId',
      'linkPublicKeyB64u',
    ]);
    expect(typeof result.handleId).toBe('string');
    expect(typeof result.linkPublicKeyB64u).toBe('string');
    expect(typeof result.devicePublicKeyB64u).toBe('string');

    scope.responses.length = 0;
    const preparation = targetPreparation();
    scope.send({
      id: 'prepare-holders',
      request: {
        kind: 'device_linking_target_holders_prepare_v1',
        handleId: result.handleId,
        preparation,
        credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
        factorSecret: new Uint8Array(32).fill(11).buffer,
      },
    });
    const holders = await waitForResponse(scope);
    expect(holders.error).toBeUndefined();
    expect(holders).toMatchObject({ ok: true });
    const holderResult = holders.result as Record<string, unknown>;
    const ordered = holderResult.orderedHolderRegistrations as Record<string, unknown>[];
    expect(ordered).toHaveLength(1);
    expect(ordered[0]).toMatchObject({
      kind: 'linked_device_target_holder_registration_v1',
      operationId: preparation.orderedChildren[0].operationId,
      walletKeyId: preparation.orderedChildren[0].walletKeyId,
      keyFamily: preparation.orderedChildren[0].keyFamily,
      targetLaneId: preparation.orderedChildren[0].targetLaneId,
      targetLaneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
      targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
    });
    expect(ordered[0]).not.toHaveProperty('factorSecret');
    expect(JSON.stringify(holderResult)).not.toContain('prf');

    scope.responses.length = 0;
    scope.send({
      id: 'sign',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'POST',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1/credential',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const signed = await waitForResponse(scope);
    expect(signed.ok).toBe(true);
    const signature = (signed.result as Record<string, unknown>).signatureB64u;
    expect(typeof signature).toBe('string');
    expect(base64UrlEncode(new Uint8Array(64))).not.toBe(signature);

    scope.responses.length = 0;
    scope.send({
      id: 'discard',
      request: { kind: 'device_linking_key_material_discard_v1', handleId: result.handleId },
    });
    await waitForResponse(scope);
    scope.responses.length = 0;
    scope.send({
      id: 'sign-after-discard',
      request: {
        kind: 'device_linking_request_sign_v1',
        handleId: result.handleId,
        linkSessionId: 'link-session-1',
        method: 'GET',
        canonicalPath: '/wallet/device-linking/v1/sessions/link-session-1',
        bodyDigestB64u: digest(3),
        devicePublicKeyDigestB64u: digest(9),
        challengeB64u: challenge(),
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
      },
    });
    const discarded = await waitForResponse(scope);
    expect(discarded.ok).toBe(false);
    expect(discarded.error).toContain('unknown or discarded');
    expect(recipientsDestroyed).toBe(1);
    installed.close();
  });

  test('transfers PRF output to the worker and returns an attestation-only projection', async () => {
    const preparation = targetPreparation();
    const credentialIdB64u = base64UrlEncode(new Uint8Array(32).fill(8));
    const prfFirstB64u = base64UrlEncode(new Uint8Array(32).fill(11));
    const authenticator: AuthenticatorPort = {
      kind: 'authenticator',
      async run() {
        return {
          ok: true,
          operation: 'create_passkey',
          requirePrfFirst: true,
          credential: {
            id: credentialIdB64u,
            rawId: credentialIdB64u,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: base64UrlEncode(new Uint8Array([1])),
              attestationObject: base64UrlEncode(new Uint8Array([2])),
              transports: ['internal'],
            },
            clientExtensionResults: {
              prf: { results: { first: prfFirstB64u, second: undefined } },
            },
          },
          credentialIdB64u,
          rawIdB64u: credentialIdB64u,
          rpId: toRpId(preparation.rpId),
          prf: { kind: 'required', prfFirstB64u },
        };
      },
    };
    let transferredFactorSecret: Uint8Array | null = null;
    const keyMaterial: DeviceLinkingKeyMaterialPortV1 = {
      async createBootstrapKeyMaterialV1() {
        throw new Error('bootstrap is outside this test');
      },
      async prepareTargetHolderRegistrationsV1(input) {
        transferredFactorSecret = new Uint8Array(input.factorSecret).slice();
        return {
          orderedHolderRegistrations: [
            {
              kind: 'linked_device_target_holder_registration_v1',
              operationId: preparation.orderedChildren[0].operationId,
              walletKeyId: preparation.orderedChildren[0].walletKeyId,
              keyFamily: preparation.orderedChildren[0].keyFamily,
              targetLaneId: preparation.orderedChildren[0].targetLaneId,
              targetLaneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
              targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
              holderParticipant: {
                kind: 'lane_holder_participant_v1',
                participantId: preparation.orderedChildren[0].targetHolderParticipantId,
                custodyBindingId: 'lane-custody-1',
                custodyBindingDigestB64u: digest(41),
                hpkePublicKeyB64u: digest(51),
                hpkePublicKeyDigestB64u: digest(61),
                participantBindingDigestB64u: digest(71),
              },
            },
          ],
        };
      },
      async discardKeyMaterialV1() {},
      async signDeviceSessionRequestV1() {
        throw new Error('signing is outside this test');
      },
    };
    const port = createDeviceLinkingTargetCredentialPortV1({ authenticator, keyMaterial });
    const result = await port.createTargetCredentialV1({
      preparation,
      keyMaterial: { kind: 'device_linking_key_material_handle_v1', handleId: 'handle-1' },
    });
    expect(transferredFactorSecret).toEqual(new Uint8Array(32).fill(11));
    expect(result.webauthnRegistration).not.toHaveProperty('clientExtensionResults');
    expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
    expect(result.orderedHolderRegistrations).toHaveLength(1);
  });
});
