import { expect, test } from '@playwright/test';
import {
  buildEcdsaOperationStepUpPreparation,
  prepareEcdsaOperationStepUp,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ecdsa/operationStepUp';
import {
  computeRouterAbEcdsaOperationStepUpChallengeB64u,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseRootShareEpoch } from '../../packages/shared-ts/src/utils/domainIds';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

// The Passkey challenge must be the canonical digest of the exact prepared
// operation, and the server recomputes it from the parsed preparation with the
// same shared helper. If these diverge, a Passkey step-up signature is verified
// against a different operation than the user approved.

const WALLET_ID = 'wallet-1';

function b64u(seed: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(seed)).toString('base64url');
}

function digest(seed: number): ReturnType<typeof parseDigestB64u> {
  return parseDigestB64u(b64u(seed, 32));
}

const materialActivation = buildMpcMaterialActivationRefFixture('step-up-binding', WALLET_ID);

function fixtureActivationEpoch(value: string) {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) throw new Error(`invalid fixture activation epoch: ${value}`);
  return parsed.value;
}

const normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1 = {
  wallet_id: WALLET_ID,
  ecdsa_threshold_key_id: 'ecdsa-key-1',
  signing_root_id: 'root-1',
  signing_root_version: 'root-v1',
  context: {
    application_binding_digest_b64u: b64u(7, 32),
  },
  public_identity: {
    context_binding_b64u: b64u(1, 32),
    derivation_client_share_public_key33_b64u: b64u(2, 33),
    server_public_key33_b64u: b64u(3, 33),
    threshold_public_key33_b64u: b64u(2, 33),
    ethereum_address20_b64u: b64u(5, 20),
    client_share_retry_counter: 0,
    server_share_retry_counter: 1,
  },
  signing_worker: {
    server_id: String(materialActivation.signingWorker),
    key_epoch: 'worker-epoch-1',
    recipient_encryption_key:
      'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  activation_epoch: fixtureActivationEpoch('activation-1'),
};

function preparationArgs() {
  return {
    walletId: WALLET_ID,
    operationKind: 'evm.sign_transaction' as const,
    operationId: 'operation-1',
    operationDigests: {
      laneDigest: digest(11),
      intentDigest: digest(12),
      displayDigest: digest(13),
    },
    materialActivation,
    normalSigningScope,
    evmFamilySigningKeySlotId: 'slot-1',
    keyHandle: 'key-handle-1',
    relayerKeyId: 'relayer-key-1',
    participantIds: [1, 2] as const,
    expiresAtMs: Date.now() + 5 * 60_000,
  };
}

function explicitExportRequest(operationKind: 'evm.export_key' | 'evm.sign_transaction') {
  const operation = buildEcdsaOperationStepUpPreparation({
    ...preparationArgs(),
    operationKind,
  });
  const server = normalSigningScope.signing_worker;
  const publicDigest = { bytes: new Array<number>(32).fill(1) };
  return {
    context: normalSigningScope.context,
    lifecycle: {
      lifecycle_id: 'export-lifecycle-1',
      work_kind: 'key_export',
      primitive_request_kind: 'export',
      root_share_epoch: normalSigningScope.activation_epoch,
      account_id: WALLET_ID,
      session_id: 'threshold-session-1',
      signer_set_id: 'signer-set-1',
      selected_server_id: server.server_id,
    },
    public_identity: normalSigningScope.public_identity,
    signer_set: {
      signer_set_id: 'signer-set-1',
      policy: 'all_2',
      signer_a: { role: 'signer_a', signer_id: 'signer-a', key_epoch: 'epoch-a' },
      signer_b: { role: 'signer_b', signer_id: 'signer-b', key_epoch: 'epoch-b' },
      selected_server: server,
    },
    router_id: 'router-1',
    client_id: WALLET_ID,
    client_ephemeral_public_key: `x25519:${'a'.repeat(64)}`,
    authorization: { kind: 'operation_step_up', grant_id: 'grant-1' },
    operation,
    material_activation_id: String(materialActivation.activationId),
    export_authorization_digest_b64u: b64u(21, 32),
    export_nonce: 'export-nonce-1',
    expires_at_ms: operation.expires_at_ms,
    deriver_a_export_envelope: {
      recipient_role: 'signer_a',
      header_digest: publicDigest,
      aad_digest: publicDigest,
      ciphertext: { bytes: [1] },
    },
    deriver_b_export_envelope: {
      recipient_role: 'signer_b',
      header_digest: publicDigest,
      aad_digest: publicDigest,
      ciphertext: { bytes: [2] },
    },
  };
}

test.describe('ECDSA operation step-up challenge binding', () => {
  test('prepared challenge equals the digest the server derives from the same operation', async () => {
    const prepared = await prepareEcdsaOperationStepUp(preparationArgs());

    // Exactly what the Gateway recomputes from the parsed preparation before
    // verifying the WebAuthn assertion.
    const serverExpected = await computeRouterAbEcdsaOperationStepUpChallengeB64u(
      prepared.operation,
    );

    expect(prepared.operation.operation_kind).toBe('evm.sign_transaction');
    expect(prepared.challengeB64u).toBe(serverExpected);
    expect(prepared.challengeB64u.length).toBeGreaterThan(0);
  });

  test('challenge changes when a bound operation field changes', async () => {
    const baseline = await prepareEcdsaOperationStepUp(preparationArgs());

    const changedIntent = await prepareEcdsaOperationStepUp({
      ...preparationArgs(),
      operationDigests: {
        laneDigest: digest(11),
        intentDigest: digest(99),
        displayDigest: digest(13),
      },
    });
    expect(changedIntent.challengeB64u).not.toBe(baseline.challengeB64u);

    const changedOperationId = await prepareEcdsaOperationStepUp({
      ...preparationArgs(),
      operationId: 'operation-2',
    });
    expect(changedOperationId.challengeB64u).not.toBe(baseline.challengeB64u);

    const changedOperationKind = await prepareEcdsaOperationStepUp({
      ...preparationArgs(),
      operationKind: 'evm.export_key',
    });
    expect(changedOperationKind.operation.operation_kind).toBe('evm.export_key');
    expect(changedOperationKind.challengeB64u).not.toBe(baseline.challengeB64u);
  });

  test('one prepared operation yields one stable challenge', async () => {
    const operation = buildEcdsaOperationStepUpPreparation(preparationArgs());
    const first = await computeRouterAbEcdsaOperationStepUpChallengeB64u(operation);
    const second = await computeRouterAbEcdsaOperationStepUpChallengeB64u(operation);
    expect(first).toBe(second);
  });

  test('explicit export requires an export preparation only on the step-up branch', () => {
    const stepUp = explicitExportRequest('evm.export_key');
    const parsed = parseRouterAbEcdsaDerivationExplicitExportRequestV1(stepUp);
    expect(parsed.authorization.kind).toBe('operation_step_up');
    expect(parsed.operation?.operation_kind).toBe('evm.export_key');

    const { operation: _missing, ...withoutOperation } = stepUp;
    expect(() => parseRouterAbEcdsaDerivationExplicitExportRequestV1(withoutOperation)).toThrow();

    expect(() =>
      parseRouterAbEcdsaDerivationExplicitExportRequestV1({
        ...stepUp,
        authorization: {
          kind: 'reusable_wallet_session',
          wallet_session_id: 'wallet-session-1',
        },
      }),
    ).toThrow();
  });
});
