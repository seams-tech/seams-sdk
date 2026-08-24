import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletKeyId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
} from '../../packages/shared-ts/src/authorization/walletAuthority';
import { buildSigningOnlyPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { parseExactAdministeredSignerManifestV1 } from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import { parseCommittedAuthorityPackagesV1 } from '../../packages/shared-ts/src/device-linking/committedSignerPackages';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { requireRouterAbEcdsaDerivationNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { parseEcdsaThresholdKeyId } from '../../packages/wallet/src/core/signingEngine/session/keyMaterialBrands';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/wallet/src/core/signingEngine/workerManager/workers/device-linking-key.worker';
import {
  assertOrdinaryExportRootResealingMatchesIdentityV1,
  parseOrdinaryMaterialWorkerRequestV1,
  parseOrdinarySignerMaterialRecipientPreparationV1,
  parseOrdinaryResealedExportRootRecordV1,
  type DeviceLinkingOrdinaryMaterialSealerV1,
} from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingOrdinaryMaterialWorker';
import type { DeviceLinkingResealedEd25519ExportRootV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingEd25519ExportRoot';
import {
  buildR103DeviceLinkFixture,
  buildR103EcdsaSourceContributionPreparationV1,
  buildR103EcdsaSourceContributionV1,
} from './helpers/deviceLinkContracts.fixtures';
import { buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture } from './helpers/passkeyCustodyEnvelope.fixtures';

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

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
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
  test('accepts only the custody-worker resealed export-root record', () => {
    const authorityId = parseWalletAuthorityId('authority:ordinary-seal-test');
    const walletAuthMethodId = parseWalletAuthMethodId('auth-method:ordinary-seal-test');
    const walletKeyId = parseWalletKeyId('wallet-key:ordinary-seal-test');
    if (!authorityId.ok || !walletAuthMethodId.ok || !walletKeyId.ok) {
      throw new Error('ordinary export-root identity fixture is invalid');
    }
    const resealed: DeviceLinkingResealedEd25519ExportRootV1 = {
      envelope: buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture({
        tag: 'ordinary-seal-test',
        walletId: 'wallet:ordinary-seal-test',
        walletKeyId: walletKeyId.value,
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
        rpId: 'example.test',
        credentialIdB64u: base64UrlEncode(new Uint8Array([1])),
        deviceId: 'device:ordinary-seal-test',
        sealedFill: 7,
      }),
    };
    expect(
      assertOrdinaryExportRootResealingMatchesIdentityV1({
        authorityId: authorityId.value,
        walletAuthMethodId: walletAuthMethodId.value,
        walletKeyId: walletKeyId.value,
        resealedExportRoot: resealed,
      }),
    ).toEqual({
      kind: 'wallet_authority_export_root_v1',
      authorityId: authorityId.value,
      walletAuthMethodId: walletAuthMethodId.value,
      walletKeyId: walletKeyId.value,
      envelope: resealed.envelope,
    });
    expect(() =>
      assertOrdinaryExportRootResealingMatchesIdentityV1({
        authorityId: authorityId.value,
        walletAuthMethodId: walletAuthMethodId.value,
        walletKeyId: walletKeyId.value,
        resealedExportRoot: null,
      }),
    ).toThrow('requires an Ed25519 export-root result');
    expect(() =>
      assertOrdinaryExportRootResealingMatchesIdentityV1({
        authorityId: authorityId.value,
        walletAuthMethodId: walletAuthMethodId.value,
        walletKeyId: null,
        resealedExportRoot: resealed,
      }),
    ).toThrow('without a package');
    expect(() =>
      parseOrdinaryResealedExportRootRecordV1({
        kind: 'linked_device_ed25519_export_root_package_v1',
        sealedExportRootB64u: resealed.envelope.sealedCustodySecretB64u,
      }),
    ).toThrow('unsupported');
  });

  test('keeps ordinary recipient inputs inside the worker boundary', () => {
    const requirements = [
      {
        kind: 'ordinary_signer_material_recipient_requirement_v1',
        keyFamily: 'ed25519',
        walletKeyId: 'wallet-key:ordinary-recipient-boundary',
      },
    ] as const;
    expect(() =>
      parseOrdinaryMaterialWorkerRequestV1({
        kind: 'device_linking_ordinary_signer_material_recipient_prepare_v1',
        handleId: 'device-linking-key-boundary',
        requirements,
        recipientInputs: [
          {
            kind: 'ordinary_ed25519_signer_material_recipient_input_v1',
            keyFamily: 'ed25519',
            walletKeyId: requirements[0].walletKeyId,
            recipientPrivateKey: new ArrayBuffer(32),
          },
        ],
      }),
    ).toThrow('recipientInputs is unsupported');

    expect(() =>
      parseOrdinaryMaterialWorkerRequestV1({
        kind: 'device_linking_ordinary_signer_material_prepare_private_v1',
        handleId: 'device-linking-key-boundary',
        targetFactor: {
          kind: 'passkey',
          walletAuthMethodId: 'auth-method:ordinary-recipient-boundary',
          verificationDigestB64u: digest(4),
          rpId: 'example.test',
          credentialIdB64u: base64UrlEncode(new Uint8Array([1])),
        },
        preparations: [],
        recipientRequests: [],
        recipientInputs: [],
        factorSecret: new ArrayBuffer(32),
      }),
    ).toThrow('ordinary material worker request kind is unsupported');
  });

  test('pairs each public ordinary recipient request with its private input', () => {
    const ed25519PrivateKey = new ArrayBuffer(32);
    const ecdsaPrivateKey = new ArrayBuffer(32);
    const parsed = parseOrdinarySignerMaterialRecipientPreparationV1({
      kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1',
      recipientRequests: [
        {
          kind: 'ordinary_ed25519_signer_material_recipient_request_v1',
          keyFamily: 'ed25519',
          walletKeyId: 'wallet-key:ordinary-ed25519',
          recipientPublicKeyB64u: base64UrlEncode(new Uint8Array(32)),
        },
        {
          kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
          keyFamily: 'ecdsa_secp256k1',
          walletKeyId: 'wallet-key:ordinary-ecdsa',
          clientEphemeralPublicKey: 'x25519:01020304',
        },
      ],
      recipientInputs: [
        {
          kind: 'ordinary_ed25519_signer_material_recipient_input_v1',
          keyFamily: 'ed25519',
          walletKeyId: 'wallet-key:ordinary-ed25519',
          recipientPrivateKey: ed25519PrivateKey,
        },
        {
          kind: 'ordinary_ecdsa_signer_material_recipient_input_v1',
          keyFamily: 'ecdsa_secp256k1',
          walletKeyId: 'wallet-key:ordinary-ecdsa',
          clientEphemeralPrivateKey: ecdsaPrivateKey,
        },
      ],
    });
    expect(parsed.recipientInputs).toHaveLength(2);
    expect(parsed.recipientRequests[0]?.keyFamily).toBe('ed25519');
    expect(parsed.recipientInputs[1]?.keyFamily).toBe('ecdsa_secp256k1');

    expect(() =>
      parseOrdinarySignerMaterialRecipientPreparationV1({
        kind: 'device_linking_ordinary_signer_material_recipient_preparation_v1',
        recipientRequests: parsed.recipientRequests,
        recipientInputs: [parsed.recipientInputs[1], parsed.recipientInputs[0]],
      }),
    ).toThrow('ordinary recipient requests must be ordered Ed25519 then ECDSA');
  });

  test('creates paired ordinary recipients inside the key worker', async () => {
    const scope = new FakeWorkerScope();
    const installed = installDeviceLinkingKeyWorkerV1(scope);
    scope.send({
      id: 'create-ordinary-recipient-slot',
      request: { kind: 'device_linking_key_material_create_v1' },
    });
    const created = await waitForResponse(scope);
    scope.responses.shift();
    const createdResult = created.result as Record<string, unknown>;
    const handleId = String(createdResult.handleId);
    scope.send({
      id: 'prepare-ordinary-recipients',
      request: {
        kind: 'device_linking_ordinary_signer_material_recipient_prepare_v1',
        handleId,
        requirements: [
          {
            kind: 'ordinary_signer_material_recipient_requirement_v1',
            keyFamily: 'ed25519',
            walletKeyId: 'wallet-key:ordinary-worker-ed25519',
          },
          {
            kind: 'ordinary_signer_material_recipient_requirement_v1',
            keyFamily: 'ecdsa_secp256k1',
            walletKeyId: 'wallet-key:ordinary-worker-ecdsa',
          },
        ],
      },
    });
    const prepared = await waitForResponse(scope);
    expect(prepared).toMatchObject({ ok: true });
    const preparation = prepared.result as {
      readonly recipientRequests: readonly Record<string, unknown>[];
      readonly recipientInputs: readonly Record<string, unknown>[];
    };
    expect(preparation.recipientRequests).toHaveLength(2);
    expect(preparation.recipientInputs).toHaveLength(2);
    expect(preparation.recipientRequests[0]).toMatchObject({
      keyFamily: 'ed25519',
      walletKeyId: 'wallet-key:ordinary-worker-ed25519',
    });
    expect(preparation.recipientRequests[1]).toMatchObject({
      keyFamily: 'ecdsa_secp256k1',
      walletKeyId: 'wallet-key:ordinary-worker-ecdsa',
    });
    expect(preparation.recipientInputs[0]?.recipientPrivateKey).toBeInstanceOf(ArrayBuffer);
    expect(preparation.recipientInputs[1]?.clientEphemeralPrivateKey).toBeInstanceOf(ArrayBuffer);
    scope.responses.shift();
    scope.send({
      id: 'discard-ordinary-recipient-slot',
      request: { kind: 'device_linking_key_material_discard_v1', handleId },
    });
    await waitForResponse(scope);
    await installed.close();
  });

  test('zeroizes transferred ordinary material while preserving idempotent worker-owned state', async () => {
    const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:worker-duplicate' });
    const authorityId = required(parseWalletAuthorityId('authority:worker-duplicate'));
    const walletAuthMethodId = required(parseWalletAuthMethodId('passkey:worker-duplicate'));
    const walletId = required(parseWalletId('wallet:r103'));
    const walletKeyId = required(parseWalletKeyId('wallet-key:worker-duplicate'));
    const deviceId = fixture.approval.deviceId;
    const enrollmentId = fixture.approval.enrollmentId;
    const linkSessionId = fixture.approval.linkSessionId;
    const sourceContribution = buildR103EcdsaSourceContributionV1(fixture);
    const preparation = buildR103EcdsaSourceContributionPreparationV1(fixture);
    const targetActivation = preparation[0]?.target.activation;
    if (!targetActivation) throw new Error('duplicate preparation target activation is missing');
    const thresholdPublicKey33B64u = sourceContribution.sourceSigner.thresholdPublicKey33B64u;
    const signerManifest = parseExactAdministeredSignerManifestV1({
      kind: 'exact_administered_signer_manifest_v1',
      keyFamilies: ['ecdsa_secp256k1'],
      signers: [
        {
          kind: 'exact_administered_ecdsa_signer_v1',
          keyFamily: 'ecdsa_secp256k1',
          walletId,
          walletKeyId,
          thresholdPublicKey33B64u,
          evmAddress: '0x1111111111111111111111111111111111111111',
        },
      ],
    });
    const signerActivations = buildWalletSignerActivationSetV1({
      manifest: signerManifest,
      materialActivations: { keyFamilies: ['ecdsa_secp256k1'], ecdsa: targetActivation },
    });
    const packageSetDigestB64u = fixture.packageSetDigestB64u;
    const pendingAuthority = buildPendingWalletAuthorityV1({
      kind: 'wallet_authority_v1',
      authorityId,
      walletId,
      principal: { kind: 'owner_device', deviceId },
      provenance: {
        kind: 'device_link',
        enrollmentId,
        sourceAuthorityId: 'authority:r103',
        linkSessionId,
      },
      permissions: buildSigningOnlyPermissionsV1(),
      signerActivations,
      signerActivationSetDigestB64u: packageSetDigestB64u,
      authorityDigestB64u: packageSetDigestB64u,
      revocationEpoch: 0,
      createdAtMs: 100,
      updatedAtMs: 100,
      state: 'pending_local_install',
      localInstallPackageSetDigestB64u: packageSetDigestB64u,
    });
    const rpId = required(parseWebAuthnRpId('wallet.example.test'));
    const credentialIdB64u = required(
      parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
    );
    const authMethod = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'passkey',
      status: 'pending_local_install',
      rpId,
      credentialIdB64u,
      credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
      counter: 0,
      createdAtMs: 100,
      updatedAtMs: 100,
    });
    if (authMethod.status !== 'pending_local_install') {
      throw new Error('duplicate preparation auth method fixture is not pending');
    }
    const sourceNormalSigning = sourceContribution.sourceDerivation.sourceNormalSigning;
    const sourceNormalSigningScope = sourceNormalSigning.scope;
    const targetRecipientKeyHex = Array.from(
      base64UrlDecode(
        sourceContribution.package.binding.target.signingWorkerRecipientPublicKeyB64u,
      ),
      (byte) => byte.toString(16).padStart(2, '0'),
    ).join('');
    const targetNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: {
        wallet_id: sourceNormalSigningScope.wallet_id,
        ecdsa_threshold_key_id: sourceNormalSigningScope.ecdsa_threshold_key_id,
        signing_root_id: sourceNormalSigningScope.signing_root_id,
        signing_root_version: sourceNormalSigningScope.signing_root_version,
        context: sourceNormalSigningScope.context,
        public_identity: {
          ...sourceNormalSigningScope.public_identity,
          derivation_client_share_public_key33_b64u:
            sourceContribution.package.binding.targetClientPublicKey33B64u,
          server_public_key33_b64u: sourceContribution.sourceSigner.relayerPublicKey33B64u,
        },
        material_activation: routerAbMpcMaterialActivationRefToWire(targetActivation),
        signing_worker: {
          server_id: targetActivation.signingWorker,
          key_epoch: sourceNormalSigningScope.signing_worker.key_epoch,
          recipient_encryption_key: `x25519:${targetRecipientKeyHex}`,
        },
        activation_epoch: sourceNormalSigningScope.activation_epoch,
      },
    });
    const ecdsaReceipt = {
      state: 'inactive' as const,
      binding: sourceContribution.package.binding,
      sourceDerivation: sourceContribution.sourceDerivation,
      targetRelayerPublicKey33B64u: sourceContribution.sourceSigner.relayerPublicKey33B64u,
      thresholdPublicKey33B64u,
      thresholdEthereumAddress20B64u:
        sourceContribution.sourceSigner.thresholdEthereumAddress20B64u,
      normalSigning: targetNormalSigning,
    };
    const committed = parseCommittedAuthorityPackagesV1({
      kind: 'committed_authority_packages_v1',
      authority: pendingAuthority,
      authMethod,
      signerPackages: {
        kind: 'committed_signer_package_set_v1',
        keyFamilies: ['ecdsa_secp256k1'],
        ecdsa: {
          kind: 'committed_ecdsa_signer_package_v1',
          materialActivation: targetActivation,
          encryptedTargetClientShare: sourceContribution.package.encryptedTargetClientShare,
          activationReceipt: ecdsaReceipt,
        },
      },
      ed25519ExportRootPackage: null,
      packageSetDigestB64u,
    });
    const targetFactor = {
      kind: 'passkey' as const,
      walletAuthMethodId,
      verificationDigestB64u: packageSetDigestB64u,
      rpId,
      credentialIdB64u,
    };
    const scope = new FakeWorkerScope();
    const expectedFactorSecret = new Uint8Array(32).fill(71);
    let observedFactorSecret: Uint8Array | null = null;
    let observedRecipientPrivateKey: Uint8Array | null = null;
    let sealCalls = 0;
    const sealer: DeviceLinkingOrdinaryMaterialSealerV1 = {
      async sealCommittedAuthorityPackagesV1(input) {
        observedFactorSecret = input.factorSecret;
        const recipientInput = input.recipientInputs[0];
        if (
          !recipientInput ||
          recipientInput.kind !== 'ordinary_ecdsa_signer_material_recipient_input_v1'
        ) {
          throw new Error('duplicate preparation recipient input is missing');
        }
        observedRecipientPrivateKey = new Uint8Array(recipientInput.clientEphemeralPrivateKey);
        sealCalls += 1;
        const activation = input.committed.authority.signerActivations.ecdsa;
        if (!activation) throw new Error('duplicate preparation ECDSA activation is missing');
        return {
          signerMaterials: [
            {
              kind: 'wallet_authority_signer_material_v1' as const,
              authorityId: input.committed.authority.authorityId,
              walletAuthMethodId: input.committed.authMethod.walletAuthMethodId,
              activationId: activation.materialActivation.activationId,
              keyFamily: 'ecdsa_secp256k1' as const,
              ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
                sourceContribution.sourceDerivation.ecdsaThresholdKeyId,
              ),
              materialActivation: activation.materialActivation,
              sealedMaterialB64u: base64UrlEncode(new Uint8Array([sealCalls])),
              sealedMaterialDigestB64u: packageSetDigestB64u,
            },
          ],
          exportRoot: null,
          installedRecordSetDigestB64u: packageSetDigestB64u,
        };
      },
    };
    const installed = installDeviceLinkingKeyWorkerV1(scope, sealer);
    scope.send({
      id: 'create-duplicate-prepare-slot',
      request: { kind: 'device_linking_key_material_create_v1' },
    });
    const created = await waitForResponse(scope);
    scope.responses.shift();
    const handleId = String((created.result as Record<string, unknown>).handleId);
    scope.send({
      id: 'prepare-duplicate-recipients',
      request: {
        kind: 'device_linking_ordinary_signer_material_recipient_prepare_v1',
        handleId,
        requirements: [
          {
            kind: 'ordinary_signer_material_recipient_requirement_v1',
            keyFamily: 'ecdsa_secp256k1',
            walletKeyId,
          },
        ],
      },
    });
    const recipientResponse = await waitForResponse(scope);
    scope.responses.shift();
    const recipientPreparation = parseOrdinarySignerMaterialRecipientPreparationV1(
      recipientResponse.result,
    );
    const recipientInput = recipientPreparation.recipientInputs[0];
    if (
      !recipientInput ||
      recipientInput.kind !== 'ordinary_ecdsa_signer_material_recipient_input_v1'
    ) {
      throw new Error('duplicate preparation recipient input is missing');
    }
    const recipientPrivateKey = new Uint8Array(recipientInput.clientEphemeralPrivateKey).slice();
    const privateRequest = (
      factorSecret = expectedFactorSecret.slice(),
      recipientPrivateKeyInput = recipientPrivateKey.slice(),
      targetFactorInput = targetFactor,
    ) => ({
      kind: 'device_linking_ordinary_signer_material_prepare_private_v1' as const,
      handleId,
      targetFactor: targetFactorInput,
      preparations: preparation,
      recipientRequests: recipientPreparation.recipientRequests,
      recipientInputs: [
        {
          kind: recipientInput.kind,
          keyFamily: recipientInput.keyFamily,
          walletKeyId: recipientInput.walletKeyId,
          clientEphemeralPrivateKey: recipientPrivateKeyInput.buffer,
        },
      ],
      factorSecret: factorSecret.buffer,
    });
    const firstFactorSecretTransfer = expectedFactorSecret.slice();
    const firstRecipientPrivateKeyTransfer = recipientPrivateKey.slice();
    scope.send({
      id: 'prepare-duplicate-first',
      request: privateRequest(firstFactorSecretTransfer, firstRecipientPrivateKeyTransfer),
    });
    const firstPreparation = await waitForResponse(scope);
    expect(firstPreparation).toMatchObject({ ok: true });
    expect(Array.from(firstFactorSecretTransfer)).toEqual(new Array(32).fill(0));
    expect(Array.from(firstRecipientPrivateKeyTransfer)).toEqual(new Array(32).fill(0));
    scope.responses.shift();
    const secondFactorSecretTransfer = expectedFactorSecret.slice();
    const secondRecipientPrivateKeyTransfer = recipientPrivateKey.slice();
    scope.send({
      id: 'prepare-duplicate-second',
      request: privateRequest(secondFactorSecretTransfer, secondRecipientPrivateKeyTransfer),
    });
    const duplicatePreparation = await waitForResponse(scope);
    expect(duplicatePreparation).toMatchObject({ ok: true });
    expect(duplicatePreparation.result).toEqual(firstPreparation.result);
    expect(Array.from(secondFactorSecretTransfer)).toEqual(new Array(32).fill(0));
    expect(Array.from(secondRecipientPrivateKeyTransfer)).toEqual(new Array(32).fill(0));
    scope.responses.shift();
    const conflictingTargetFactor = {
      ...targetFactor,
      verificationDigestB64u: digest(73),
    };
    scope.send({
      id: 'prepare-conflicting-replay',
      request: privateRequest(
        expectedFactorSecret.slice(),
        recipientPrivateKey.slice(),
        conflictingTargetFactor,
      ),
    });
    const conflictingPreparation = await waitForResponse(scope);
    expect(conflictingPreparation).toMatchObject({
      ok: false,
      error:
        'ordinary signer material preparation conflicts with the existing activation reference',
    });
    scope.responses.shift();
    const conflictingFactorSecret = expectedFactorSecret.slice();
    conflictingFactorSecret[0] = conflictingFactorSecret[0]! + 1;
    scope.send({
      id: 'prepare-conflicting-secret-replay',
      request: privateRequest(conflictingFactorSecret, recipientPrivateKey.slice()),
    });
    const conflictingSecretPreparation = await waitForResponse(scope);
    expect(conflictingSecretPreparation).toMatchObject({
      ok: false,
      error: 'ordinary signer material preparation conflicts with the existing factor secret',
    });
    expect(Array.from(conflictingFactorSecret)).toEqual(new Array(32).fill(0));
    scope.responses.shift();
    const sealRequest = {
      kind: 'device_linking_ordinary_signer_material_seal_v1' as const,
      handleId,
      committed,
      targetFactor,
      resealedExportRoot: null,
    };
    scope.send({ id: 'seal-after-duplicate-prepare', request: sealRequest });
    const sealed = await waitForResponse(scope);
    expect(sealed).toMatchObject({ ok: true });
    scope.responses.shift();
    scope.send({ id: 'seal-exact-duplicate', request: sealRequest });
    const duplicateSealed = await waitForResponse(scope);
    expect(duplicateSealed).toMatchObject({ ok: true });
    expect(duplicateSealed.result).toEqual(sealed.result);
    expect(sealCalls).toBe(1);
    scope.responses.shift();
    scope.send({
      id: 'seal-conflicting-replay',
      request: { ...sealRequest, targetFactor: conflictingTargetFactor },
    });
    const conflictingSeal = await waitForResponse(scope);
    expect(conflictingSeal).toMatchObject({
      ok: false,
      error: 'ordinary signer material target factor binding changed',
    });
    scope.responses.shift();
    expect(observedFactorSecret).not.toBeNull();
    expect(Array.from(observedFactorSecret ?? [])).toEqual(Array.from(expectedFactorSecret));
    expect(observedRecipientPrivateKey).not.toBeNull();
    expect(Array.from(observedRecipientPrivateKey ?? [])).toEqual(Array.from(recipientPrivateKey));
    scope.send({
      id: 'discard-ordinary-material-slot',
      request: { kind: 'device_linking_key_material_discard_v1', handleId },
    });
    const discarded = await waitForResponse(scope);
    expect(discarded).toMatchObject({ ok: true });
    expect(Array.from(observedFactorSecret ?? [])).toEqual(new Array(32).fill(0));
    expect(Array.from(observedRecipientPrivateKey ?? [])).toEqual(new Array(32).fill(0));
    scope.responses.shift();
    scope.send({ id: 'seal-after-discard', request: sealRequest });
    const reused = await waitForResponse(scope);
    expect(reused).toMatchObject({
      ok: false,
      error: 'device-linking key handle is unknown or discarded',
    });
    scope.responses.shift();

    scope.send({
      id: 'create-close-cleanup-slot',
      request: { kind: 'device_linking_key_material_create_v1' },
    });
    const closeCreated = await waitForResponse(scope);
    scope.responses.shift();
    const closeHandleId = String((closeCreated.result as Record<string, unknown>).handleId);
    scope.send({
      id: 'prepare-close-cleanup-recipients',
      request: {
        kind: 'device_linking_ordinary_signer_material_recipient_prepare_v1',
        handleId: closeHandleId,
        requirements: [
          {
            kind: 'ordinary_signer_material_recipient_requirement_v1',
            keyFamily: 'ecdsa_secp256k1',
            walletKeyId,
          },
        ],
      },
    });
    const closeRecipientResponse = await waitForResponse(scope);
    scope.responses.shift();
    const closeRecipientPreparation = parseOrdinarySignerMaterialRecipientPreparationV1(
      closeRecipientResponse.result,
    );
    const closeRecipientInput = closeRecipientPreparation.recipientInputs[0];
    if (
      !closeRecipientInput ||
      closeRecipientInput.kind !== 'ordinary_ecdsa_signer_material_recipient_input_v1'
    ) {
      throw new Error('close cleanup recipient input is missing');
    }
    const closeRecipientPrivateKey = new Uint8Array(
      closeRecipientInput.clientEphemeralPrivateKey,
    ).slice();
    const closeFactorSecret = expectedFactorSecret.slice();
    scope.send({
      id: 'prepare-close-cleanup-material',
      request: {
        ...privateRequest(closeFactorSecret, closeRecipientPrivateKey),
        handleId: closeHandleId,
        recipientRequests: closeRecipientPreparation.recipientRequests,
        recipientInputs: [
          {
            kind: closeRecipientInput.kind,
            keyFamily: closeRecipientInput.keyFamily,
            walletKeyId: closeRecipientInput.walletKeyId,
            clientEphemeralPrivateKey: closeRecipientPrivateKey.buffer,
          },
        ],
      },
    });
    const closePrepared = await waitForResponse(scope);
    expect(closePrepared).toMatchObject({ ok: true });
    expect(Array.from(closeFactorSecret)).toEqual(new Array(32).fill(0));
    expect(Array.from(closeRecipientPrivateKey)).toEqual(new Array(32).fill(0));
    scope.responses.shift();
    scope.send({
      id: 'seal-close-cleanup-material',
      request: { ...sealRequest, handleId: closeHandleId },
    });
    const closeSealed = await waitForResponse(scope);
    expect(closeSealed).toMatchObject({ ok: true });
    scope.responses.shift();
    const closeObservedFactorSecret = observedFactorSecret;
    const closeObservedRecipientPrivateKey = observedRecipientPrivateKey;
    await installed.close();
    expect(Array.from(closeObservedFactorSecret ?? [])).toEqual(new Array(32).fill(0));
    expect(Array.from(closeObservedRecipientPrivateKey ?? [])).toEqual(new Array(32).fill(0));
    expectedFactorSecret.fill(0);
    recipientPrivateKey.fill(0);
    new Uint8Array(recipientInput.clientEphemeralPrivateKey).fill(0);
    new Uint8Array(closeRecipientInput.clientEphemeralPrivateKey).fill(0);
  });

  test('opens a verified Email OTP factor release once in the worker', async () => {
    const scope = new FakeWorkerScope();
    const installed = installDeviceLinkingKeyWorkerV1(scope);
    scope.send({
      id: 'create-email-otp-slot',
      request: { kind: 'device_linking_key_material_create_v1' },
    });
    const created = await waitForResponse(scope);
    scope.responses.shift();
    expect(created).toMatchObject({ ok: true });
    const createdResult = created.result as Record<string, unknown>;
    const handleId = String(createdResult.handleId);
    const workerPublicKeyB64u = String(createdResult.emailOtpReleasePublicKey65B64u);
    const workerPublicKey = base64UrlDecode(workerPublicKeyB64u);
    const serverKeyPair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );
    const workerPublicCryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      workerPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const sharedSecret = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        { name: 'ECDH', public: workerPublicCryptoKey },
        serverKeyPair.privateKey,
        256,
      ),
    );
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    );
    const challengeId = 'google-challenge-worker';
    const ownerEnrollmentId = 'email-otp-enrollment-worker';
    const enrollmentSealKeyVersion = 'email-otp-seal-v1';
    const walletId = 'wallet-r102-lifecycle';
    const linkSessionId = 'link-session-email-otp-worker';
    const linkedDeviceEnrollmentId = 'linked-device-email-otp-worker';
    const deviceId = 'device-email-otp-worker';
    const walletAuthMethodId = 'auth-method:linked-email-otp-worker';
    const baseWalletAuthMethodId = 'auth-method:base-email-otp-worker';
    const targetPreparationDigestB64u = digest(50);
    const nowMs = Date.now();
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const factorSecret = new Uint8Array(32).fill(29);
    const aad = new TextEncoder().encode(
      `seams/email-otp/factor-release/v1\0${walletId}\0${ownerEnrollmentId}\0${enrollmentSealKeyVersion}\0${challengeId}`,
    );
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        factorSecret,
      ),
    );
    const serverPublicKey = new Uint8Array(
      await globalThis.crypto.subtle.exportKey('raw', serverKeyPair.publicKey),
    );
    const verificationGrant = {
      kind: 'linked_device_email_otp_verification_grant_v1' as const,
      grantId: 'grant-email-otp-worker',
      grantToken: 'grant-token-email-otp-worker',
      challengeId,
      linkSessionId,
      walletId,
      enrollmentId: linkedDeviceEnrollmentId,
      deviceId,
      targetPreparationDigestB64u,
      baseWalletAuthMethodId,
      emailHashHex: 'ab'.repeat(32),
      registrationAuthorityId: 'registration-authority-email-otp-worker',
      providerUserId: 'provider-email-otp-worker',
      authorityDigestB64u: digest(52),
      issuedAtMs: nowMs - 1_000,
      expiresAtMs: nowMs + 60_000,
    };
    scope.send({
      id: 'open-email-otp-holder',
      request: {
        kind: 'device_linking_email_otp_factor_release_open_v1',
        handleId,
        walletId,
        linkSessionId,
        enrollmentId: linkedDeviceEnrollmentId,
        deviceId,
        walletAuthMethodId,
        baseWalletAuthMethodId,
        targetPreparationDigestB64u,
        expectedChallengeId: challengeId,
        verificationGrant,
        factorRelease: {
          kind: 'email_otp_factor_release_v1',
          challengeId,
          enrollmentId: ownerEnrollmentId,
          enrollmentSealKeyVersion,
          serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey),
          nonce12B64u: base64UrlEncode(nonce),
          ciphertextB64u: base64UrlEncode(ciphertext),
        },
      },
    });
    const opened = await waitForResponse(scope);
    scope.responses.shift();
    expect(opened).toMatchObject({
      ok: true,
      result: {
        kind: 'device_linking_email_otp_factor_release_result_v1',
        verificationGrant: { grantId: verificationGrant.grantId },
      },
    });
    const releasedFactorSecret = (opened.result as { readonly factorSecret: ArrayBuffer })
      .factorSecret;
    expect(releasedFactorSecret).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(releasedFactorSecret)[0]).toBe(29);
    new Uint8Array(releasedFactorSecret).fill(0);

    scope.send({
      id: 'reuse-discarded-email-otp-slot',
      request: {
        kind: 'device_linking_email_otp_factor_release_open_v1',
        handleId,
        walletId,
        linkSessionId,
        enrollmentId: linkedDeviceEnrollmentId,
        deviceId,
        walletAuthMethodId,
        baseWalletAuthMethodId,
        targetPreparationDigestB64u,
        expectedChallengeId: challengeId,
        verificationGrant,
        factorRelease: {
          kind: 'email_otp_factor_release_v1',
          challengeId,
          enrollmentId: ownerEnrollmentId,
          enrollmentSealKeyVersion,
          serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey),
          nonce12B64u: base64UrlEncode(nonce),
          ciphertextB64u: base64UrlEncode(ciphertext),
        },
      },
    });
    const reused = await waitForResponse(scope);
    expect(reused).toMatchObject({
      ok: false,
      error: 'device-linking Email OTP factor release has already been consumed',
    });
    await installed.close();
    workerPublicKey.fill(0);
    sharedSecret.fill(0);
    factorSecret.fill(0);
    aad.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    serverPublicKey.fill(0);
  });
});
