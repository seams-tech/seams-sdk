import { expect, test } from '@playwright/test';
import {
  buildEcdsaOperationStepUpPreparation,
  issueEcdsaOperationStepUpAuthorization,
  prepareEcdsaOperationStepUp,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ecdsa/operationStepUp';
import { WalletSessionFailureError } from '../../packages/sdk-web/src/core/signingEngine/session/lifecycle/walletSessionFailure';
import {
  computeRouterAbEcdsaOperationStepUpChallengeB64u,
  parseRouterAbEcdsaExplicitExportForwardedResponseV1,
  parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1,
  parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { buildEmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { parseRootShareEpoch } from '../../packages/shared-ts/src/utils/domainIds';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  parseRouterAbNormalSigningAuthorization,
  routerAbMpcMaterialActivationRefToWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  attachRouterAbEcdsaExplicitExportOperationV1,
  projectRouterAbEcdsaExplicitExportRequestForWasmV1,
  type RouterAbEcdsaExplicitExportRequestFactsV1,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels';

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
  material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
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
    authorization: { kind: 'operation_step_up' },
    operation,
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
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

  test('explicit-export protocol projection strips Gateway-only operation preparation', () => {
    const request = parseRouterAbEcdsaDerivationExplicitExportRequestV1(
      explicitExportRequest('evm.export_key'),
    );
    const protocolRequest =
      projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1(request);

    expect(protocolRequest).not.toHaveProperty('operation');
    expect(parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1(protocolRequest)).toEqual(
      protocolRequest,
    );
    expect(() =>
      parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1({
        ...protocolRequest,
        operation: request.operation,
      }),
    ).toThrow();
  });

  test('SigningWorker export binding preserves the verified step-up protocol label', () => {
    const binding = {
      wallet_id: WALLET_ID,
      key_handle: 'key-handle-1',
      ecdsa_threshold_key_id: normalSigningScope.ecdsa_threshold_key_id,
      signing_root_id: normalSigningScope.signing_root_id,
      signing_root_version: normalSigningScope.signing_root_version,
      activation_epoch: normalSigningScope.activation_epoch,
      signing_worker_id: normalSigningScope.signing_worker.server_id,
      context_binding_b64u: normalSigningScope.public_identity.context_binding_b64u,
      threshold_public_key33_b64u: normalSigningScope.public_identity.threshold_public_key33_b64u,
      export_request_digest_b64u: b64u(31, 32),
      export_authorization_digest_b64u: b64u(32, 32),
      export_nonce: 'export-nonce-1',
      authorization_kind: 'verified_step_up',
      authorization_id: b64u(33, 32),
      material_activation: normalSigningScope.material_activation,
      lifecycle_id: 'export-lifecycle-1',
      recipient_identity: WALLET_ID,
      recipient_public_key: `x25519:${'a'.repeat(64)}`,
      expires_at_ms: Date.now() + 5 * 60_000,
    };
    const responseBody = {
      result: 'forwarded',
      response: {
        bundles: {
          signerA: {
            kind: 'recipient_proof_bundle',
            transcriptDigestB64u: b64u(34, 32),
            payloadB64u: b64u(35, 1),
          },
          signerB: {
            kind: 'recipient_proof_bundle',
            transcriptDigestB64u: b64u(36, 32),
            payloadB64u: b64u(37, 1),
          },
        },
      },
      signing_worker_export: {
        version: 'router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1',
        algorithm: 'hpke_x25519_hkdf_sha256_aes256gcm_v1',
        binding,
        ciphertext_and_tag: new Array(49).fill(1),
      },
    };
    const response = parseRouterAbEcdsaExplicitExportForwardedResponseV1(responseBody);
    expect(response.signing_worker_export.binding.authorization_kind).toBe('verified_step_up');
    expect(response.signing_worker_export.binding.material_activation.activation_id).toBe(
      normalSigningScope.material_activation.activation_id,
    );
    expect(() =>
      parseRouterAbEcdsaExplicitExportForwardedResponseV1({
        ...responseBody,
        signing_worker_export: {
          ...responseBody.signing_worker_export,
          binding: {
            ...binding,
            material_activation: {
              kind: 'mpc_material_activation_ref',
              activationId: normalSigningScope.material_activation.activation_id,
              capability: normalSigningScope.material_activation.capability,
              materialOwner: normalSigningScope.material_activation.material_owner,
              keyBinding: normalSigningScope.material_activation.key_binding,
              lifecycleBinding: normalSigningScope.material_activation.lifecycle_binding,
              signingWorker: normalSigningScope.material_activation.signing_worker,
            },
          },
        },
      }),
    ).toThrow(/material_activation has invalid fields/);
    expect(() =>
      parseRouterAbEcdsaExplicitExportForwardedResponseV1({
        ...responseBody,
        signing_worker_export: {
          ...responseBody.signing_worker_export,
          binding: { ...binding, authorization_kind: 'operation_step_up' },
        },
      }),
    ).toThrow(/authorization_kind must be reusable_wallet_session or verified_step_up/);
  });

  test('client worker projection omits operation before strict WASM serialization', () => {
    const request = parseRouterAbEcdsaDerivationExplicitExportRequestV1(
      explicitExportRequest('evm.export_key'),
    );
    if (request.authorization.kind !== 'operation_step_up') {
      throw new Error('step-up fixture authorization branch changed');
    }
    const {
      client_ephemeral_public_key: _clientEphemeralPublicKey,
      deriver_a_export_envelope: _deriverAExportEnvelope,
      deriver_b_export_envelope: _deriverBExportEnvelope,
      ...factsWithoutEnvelopes
    } = request;
    const operation = request.operation;
    if (!operation) {
      throw new Error('step-up fixture operation branch changed');
    }
    const facts: RouterAbEcdsaExplicitExportRequestFactsV1 = {
      ...factsWithoutEnvelopes,
      authorization: { kind: 'operation_step_up' },
      operation,
      authorization_id: parseDigestB64u(b64u(32, 32)),
      deriver_recipient_keys: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-a',
          public_key: `x25519:${'a'.repeat(64)}`,
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-b',
          public_key: `x25519:${'b'.repeat(64)}`,
        },
      },
    };
    const wasmInput = projectRouterAbEcdsaExplicitExportRequestForWasmV1(facts);
    expect(wasmInput).not.toHaveProperty('operation');
    expect(wasmInput).not.toHaveProperty('authorization_id');
    expect(wasmInput.authorization).toEqual({
      kind: 'operation_step_up',
      authorization_id: facts.authorization_id,
    });

    const restored = attachRouterAbEcdsaExplicitExportOperationV1({
      facts,
      protocolRequest: projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1(request),
    });
    expect(restored.operation).toEqual(facts.operation);
  });

  test('operation step-up response carries evidence digest separately from request marker', () => {
    const evidenceSetDigest = b64u(31, 32);
    const parsed = parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1({
      ok: true,
      kind: 'verified_step_up',
      authorization: {
        kind: 'operation_step_up',
        evidence_set_digest: evidenceSetDigest,
        unseal: { kind: 'not_requested' },
      },
      expires_at_ms: Date.now() + 60_000,
    });

    expect(parsed.authorization).toEqual({
      kind: 'operation_step_up',
      evidence_set_digest: parseDigestB64u(evidenceSetDigest),
      unseal: { kind: 'not_requested' },
    });
    expect(parseRouterAbNormalSigningAuthorization({ kind: 'operation_step_up' })).toEqual({
      kind: 'operation_step_up',
    });
  });

  test('email OTP operation step-up response carries the single-use unseal grant', () => {
    const evidenceSetDigest = b64u(32, 32);
    const parsed = parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1({
      ok: true,
      kind: 'verified_step_up',
      authorization: {
        kind: 'operation_step_up',
        evidence_set_digest: evidenceSetDigest,
        unseal: {
          kind: 'email_otp_grant',
          grant: 'grant-1',
          challenge_id: 'challenge-1',
        },
      },
      expires_at_ms: Date.now() + 60_000,
    });

    expect(parsed.authorization.unseal).toEqual({
      kind: 'email_otp_grant',
      grant: 'grant-1',
      challenge_id: 'challenge-1',
    });
    expect(() =>
      parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1({
        ok: true,
        kind: 'verified_step_up',
        authorization: {
          kind: 'operation_step_up',
          evidence_set_digest: evidenceSetDigest,
          unseal: { kind: 'email_otp_grant', grant: 'grant-1' },
        },
        expires_at_ms: Date.now() + 60_000,
      }),
    ).toThrow();
  });

  test('operation step-up response rejects a missing or padded evidence digest', () => {
    const response = {
      ok: true,
      kind: 'verified_step_up',
      authorization: {
        kind: 'operation_step_up',
        evidence_set_digest: b64u(32, 32),
        unseal: { kind: 'not_requested' },
      },
      expires_at_ms: Date.now() + 60_000,
    };
    expect(() =>
      parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1({
        ...response,
        authorization: {
          kind: 'operation_step_up',
          unseal: { kind: 'not_requested' },
        },
      }),
    ).toThrow('digest must be unpadded base64url');
    expect(() =>
      parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1({
        ...response,
        authorization: {
          kind: 'operation_step_up',
          evidence_set_digest: `${response.authorization.evidence_set_digest}=`,
          unseal: { kind: 'not_requested' },
        },
      }),
    ).toThrow('digest must be unpadded base64url');
  });
});

// A structurally valid app session JWT can outlive the session row it points
// at: the row is clamped to the wallet-session quota it was minted alongside,
// so it lapses well before the token's own exp. The client cannot see that
// coming — the 401 is the only signal — so the step-up has to classify it as a
// wallet-session lifecycle failure and say what the user should do, rather than
// surfacing the transport message as an opaque signing error.
test.describe('ECDSA operation step-up session failures', () => {
  // A real request: the client parses it before it ever reaches the network, so
  // a stub would fail validation instead of exercising the response handling.
  const stepUpRequest = {
    kind: 'router_ab_ecdsa_operation_step_up_v1' as const,
    operation: buildEcdsaOperationStepUpPreparation(preparationArgs()),
    proof: {
      kind: 'email_otp' as const,
      // Built rather than hand-written: bindingId is derived from the wallet id
      // and email hash, and the parser rejects any value that does not match.
      authority: buildEmailOtpWalletAuthAuthority({
        walletId: WALLET_ID,
        provider: 'google',
        providerUserId: 'google:step-up-session-copy',
        emailHashHex: 'a'.repeat(64),
      }),
      challenge_id: 'challenge-1',
      otp_code: '123456',
    },
  } as unknown as Parameters<typeof issueEcdsaOperationStepUpAuthorization>[0]['request'];

  function respondWith(code: string, message: string) {
    return async () =>
      new Response(JSON.stringify({ ok: false, code, message }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
  }

  test('an expired session becomes a typed failure with actionable copy', async () => {
    const error = await issueEcdsaOperationStepUpAuthorization({
      relayerUrl: 'https://relay.test',
      sessionAuth: { kind: 'app_session_cookie' },
      request: stepUpRequest,
      fetchImpl: respondWith(
        'wallet_session_expired',
        'Active app session is unavailable',
      ) as unknown as typeof fetch,
    }).then(
      () => null,
      (thrown: unknown) => thrown,
    );

    expect(error).toBeInstanceOf(WalletSessionFailureError);
    expect((error as WalletSessionFailureError).failure.kind).toBe('expired');
    // The user is told what to do, not what the transport returned.
    expect((error as Error).message).toBe('Signing session expired. Sign in again to continue.');
  });

  // An identity or origin mismatch is not something signing in again fixes, so
  // it stays an untyped error carrying the server's developer-facing wording.
  test('a non-session failure stays an untyped error', async () => {
    const error = await issueEcdsaOperationStepUpAuthorization({
      relayerUrl: 'https://relay.test',
      sessionAuth: { kind: 'app_session_cookie' },
      request: stepUpRequest,
      fetchImpl: respondWith(
        'unauthorized',
        'Active app session is unavailable',
      ) as unknown as typeof fetch,
    }).then(
      () => null,
      (thrown: unknown) => thrown,
    );

    expect(error).not.toBeInstanceOf(WalletSessionFailureError);
    expect((error as Error).message).toBe(
      'ECDSA operation step-up failed: Active app session is unavailable',
    );
  });
});
