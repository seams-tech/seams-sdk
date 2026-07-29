import { expect, test } from '@playwright/test';
import { resolveHydratedSecp256k1SigningMaterial } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
import {
  authorizeEvmFamilyEcdsaOperationStepUp,
  prepareEvmFamilyEcdsaOperationStepUp,
} from '@/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import { computeRouterAbEcdsaOperationStepUpChallengeB64u } from '@shared/utils/routerAbEcdsaDerivation';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  canonicalEcdsaSealedRuntimeFixture,
  ecdsaOperationDigestSetFixture,
  ecdsaOperationStepUpAuthorizationFixture,
  evmFamilyThresholdEcdsaOperationFixture,
  hydratedEcdsaSigningMaterialFixture,
  installEcdsaNormalSigningEndpointFixture,
  type EcdsaFixtureFactor,
} from './helpers/ecdsaOperationStepUp.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { Secp256k1Engine } from '@/core/signingEngine/flows/signEvmFamily/signers/secp256k1';
import { clearAllRouterAbEcdsaDerivationClientPresignatures } from '@/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool';
import {
  EcdsaOnlineClientRequestType,
  EcdsaPresignClientRequestType,
} from '@/core/signingEngine/workerManager/workerTypes';

// The canonical normal-signing path at its two boundaries -- hydration and
// operation step-up. Manifest plus exact sealed runtime resolve the material,
// the worker rehydrates it, the step-up binds the canonical challenge, and the
// grant comes back attached to the signing material. Both factors run the same
// path -- only the sealed record's auth binding differs -- which is the point
// of an auth-neutral candidate.
//
// Scope, precisely: the worker is stubbed at `requestWorkerOperation` (the
// same seam the deleted record-backed rehydration coverage used) and the
// relayer at `fetch`. Confirmation UI and the actual digest signature are not
// exercised here -- the literal signed bytes are E2E
// coverage, not this file's claim.

for (const factor of ['passkey', 'email_otp'] as const) {
  test(`canonical ${factor} normal signing reaches worker binding`, async () => {
    const { fixture, runtime, worker } = await canonicalEcdsaSealedRuntimeFixture(factor);
    const { capability, manifest } = fixture;
    expect(runtime.authBinding.kind).toBe(factor);

    const resolution = await resolveHydratedSecp256k1SigningMaterial({
      capability,
      runtime,
      requestLabel: runtime.chainTarget.kind,
      materialActivation: manifest.activation.materialActivation,
      workerCtx: worker,
    });

    if (resolution.kind !== 'ready') {
      throw new Error(`${factor} hydration was unavailable: ${resolution.reason}`);
    }

    // The worker was actually reached, and the material it returned is bound to
    // the exact activation the manifest names.
    expect(worker.requests.length).toBeGreaterThan(0);
    expect(resolution.material.kind).toBe('hydrated_ecdsa_signer_material');
    expect(String(resolution.material.materialActivation.activationId)).toBe(
      String(manifest.activation.materialActivation.activationId),
    );
    expect(resolution.material.clientShare.kind).toBe('role_local_worker_share');

    // Session-scoped state comes from the sealed runtime, not the token.
    expect(String(resolution.material.thresholdSessionId)).toBe(
      String(runtime.sealedRecord.thresholdSessionId),
    );
    expect(resolution.material.chainTarget).toEqual(runtime.chainTarget);

    // Hydrated material is auth-neutral: it carries no authorization and no
    // bearer credential of its own.
    expect(resolution.material.authorization).toBeUndefined();
    expect(resolution.material.credential).toBeUndefined();
    expect(resolution.material.walletSessionJwt).toBeUndefined();
  });
}

test('persisted ECDSA hydration binds the worker and signs the exact authorized operation', async () => {
  clearAllRouterAbEcdsaDerivationClientPresignatures();
  const { fixture, runtime, worker } = await canonicalEcdsaSealedRuntimeFixture('passkey');
  const hydration = await resolveHydratedSecp256k1SigningMaterial({
    capability: fixture.capability,
    runtime,
    requestLabel: runtime.chainTarget.kind,
    materialActivation: fixture.manifest.activation.materialActivation,
    workerCtx: worker,
  });
  if (hydration.kind !== 'ready') throw new Error(`hydration failed: ${hydration.reason}`);
  const operation = evmFamilyThresholdEcdsaOperationFixture({ operationId: OPERATION_ID });
  const prepared = await prepareEvmFamilyEcdsaOperationStepUp({
    operation,
    operationDigests,
    material: hydration.material,
  });
  const grantRequests: unknown[] = [];
  const restoreGrantFetch = stubGrantEndpoint(grantRequests);
  let ready;
  try {
    ready = await authorizeEvmFamilyEcdsaOperationStepUp({
      relayerUrl: 'https://relayer.example.test',
      sessionAuth: { kind: 'app_session_cookie' },
      authority: fixture.authority,
      authorization: ecdsaOperationStepUpAuthorizationFixture('passkey'),
      prepared,
      material: hydration.material,
    });
  } finally {
    restoreGrantFetch();
  }

  const endpoint = installEcdsaNormalSigningEndpointFixture();
  try {
    const signature = await new Secp256k1Engine({ workerCtx: worker }).signReady(
      {
        kind: 'digest',
        algorithm: 'secp256k1',
        digest32: base64UrlDecode(operationDigests.intentDigest),
      },
      ready,
      operation,
      operationDigests,
    );
    expect(signature).toEqual(endpoint.signature65);
    expect(signature).toHaveLength(65);
  } finally {
    endpoint.restore();
    clearAllRouterAbEcdsaDerivationClientPresignatures();
  }

  expect(endpoint.requests).toHaveLength(2);
  for (const request of endpoint.requests) {
    expect(request.request.operation_id).toBe(OPERATION_ID);
    expect(request.request.material_activation.activation_id).toBe(
      String(fixture.manifest.activation.materialActivation.activationId),
    );
    expect(request.request.operation_digests).toEqual({
      lane_digest_b64u: operationDigests.laneDigest,
      intent_digest_b64u: operationDigests.intentDigest,
      display_digest_b64u: operationDigests.displayDigest,
    });
  }
  expect(worker.requests).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        kind: 'ecdsaPresignClient',
        request: expect.objectContaining({ type: EcdsaPresignClientRequestType.ListAvailable }),
      }),
      expect.objectContaining({
        kind: 'ecdsaOnlineClient',
        request: expect.objectContaining({
          type: EcdsaOnlineClientRequestType.ComputeSignatureShare,
        }),
      }),
      expect.objectContaining({
        kind: 'evmCrypto',
        request: expect.objectContaining({
          type: 'verifySecp256k1RecoverableSignatureAgainstPublicKey33',
        }),
      }),
    ]),
  );
});

test('activation mismatch fails before the worker is reached', async () => {
  const { fixture, runtime, worker } = await canonicalEcdsaSealedRuntimeFixture('passkey');
  const { capability, manifest } = fixture;

  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    requestLabel: runtime.chainTarget.kind,
    // A different activation than the manifest names.
    materialActivation: buildMpcMaterialActivationRefFixture(
      'operating-path-other-activation',
      String(manifest.signer.walletId),
    ),
    workerCtx: worker,
  });

  expect(resolution).toMatchObject({
    kind: 'unavailable',
    reason: 'material_activation_mismatch',
  });
  // The gate is before hydration: no worker request was issued, so no material
  // was opened for an activation the manifest does not name.
  expect(worker.requests).toHaveLength(0);
});

test('a chain the runtime does not serve fails before the worker is reached', async () => {
  const { fixture, runtime, worker } = await canonicalEcdsaSealedRuntimeFixture('email_otp');
  const { capability, manifest } = fixture;
  const otherChain = runtime.chainTarget.kind === 'evm' ? 'tempo' : 'evm';

  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    requestLabel: otherChain,
    materialActivation: manifest.activation.materialActivation,
    workerCtx: worker,
  });

  expect(resolution).toMatchObject({ kind: 'unavailable', reason: 'chain_mismatch' });
  expect(worker.requests).toHaveLength(0);
});

// The rest of the operating path: the material hydrated above is what the
// operation step-up is prepared against, and the grant that comes back is
// attached to the signing material for exactly one operation. The relayer is
// stubbed at `fetch` -- the only network seam on this path -- so everything
// from preparation through grant attachment is production code.

const OPERATION_ID = 'operating-path-operation-1';
const GRANT_ID = 'operating-path-grant-1';
const operationDigests = ecdsaOperationDigestSetFixture();

/** Stands in for the relayer's operation step-up grant endpoint. Records every
 * request so a test can assert exactly one grant was issued. */
function stubGrantEndpoint(requests: unknown[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    requests.push(JSON.parse(String(init?.body || '{}')));
    return new Response(
      JSON.stringify({
        ok: true,
        kind: 'operation_step_up',
        authorization: { kind: 'operation_step_up', grant_id: GRANT_ID },
        authorization_session_id: 'operating-path-auth-session-1',
        expires_at_ms: Date.now() + 5 * 60_000,
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };
  return () => {
    globalThis.fetch = original;
  };
}

for (const factor of ['passkey', 'email_otp'] as const) {
  test(`canonical ${factor} material authorizes one operation by step-up`, async () => {
    const { fixture, material } = await hydratedEcdsaSigningMaterialFixture(factor);
    const { authority } = fixture;

    const prepared = await prepareEvmFamilyEcdsaOperationStepUp({
      operation: evmFamilyThresholdEcdsaOperationFixture({ operationId: OPERATION_ID }),
      operationDigests,
      material,
    });

    // The challenge the user approves is the canonical digest of this exact
    // operation -- the same value the Gateway recomputes before verifying.
    expect(prepared.challengeB64u).toBe(
      await computeRouterAbEcdsaOperationStepUpChallengeB64u(prepared.operation),
    );
    expect(prepared.operation.operation_id).toBe(OPERATION_ID);
    expect(prepared.operation.material_activation.activation_id).toBe(
      String(material.materialActivation.activationId),
    );

    const grantRequests: unknown[] = [];
    const restoreFetch = stubGrantEndpoint(grantRequests);
    let ready;
    try {
      ready = await authorizeEvmFamilyEcdsaOperationStepUp({
        relayerUrl: 'https://relayer.example.test',
        sessionAuth: { kind: 'app_session_cookie' },
        authority,
        authorization: ecdsaOperationStepUpAuthorizationFixture(factor),
        prepared,
        material,
      });
    } finally {
      restoreFetch();
    }

    // Exactly one grant, for exactly this operation.
    expect(grantRequests).toHaveLength(1);
    expect(ready.authorization).toEqual({ kind: 'operation_step_up', grant_id: GRANT_ID });
    expect(ready.operationStepUpPreparation).toEqual(prepared.operation);
    expect(String(ready.signerSession.materialActivation.activationId)).toBe(
      String(material.materialActivation.activationId),
    );

    // No reusable Wallet Session was created or read anywhere on this path.
    expect(ready.singleUseEmailOtpSession).toBe(false);
    expect(ready.credential).toEqual({ kind: 'app_session_cookie' });
  });

  test(`a ${factor} step-up cannot prove against the other factor's authority`, async () => {
    const { fixture, material } = await hydratedEcdsaSigningMaterialFixture(factor);
    const { authority } = fixture;
    const otherFactor: EcdsaFixtureFactor = factor === 'passkey' ? 'email_otp' : 'passkey';
    const prepared = await prepareEvmFamilyEcdsaOperationStepUp({
      operation: evmFamilyThresholdEcdsaOperationFixture({ operationId: OPERATION_ID }),
      operationDigests,
      material,
    });
    const grantRequests: unknown[] = [];
    const restoreFetch = stubGrantEndpoint(grantRequests);
    try {
      await expect(
        authorizeEvmFamilyEcdsaOperationStepUp({
          relayerUrl: 'https://relayer.example.test',
          sessionAuth: { kind: 'app_session_cookie' },
          authority,
          // The proof is built for the wrong factor for this capability.
          authorization: ecdsaOperationStepUpAuthorizationFixture(otherFactor),
          prepared,
          material,
        }),
      ).rejects.toThrow(/exact (passkey|Email OTP) authority/);
    } finally {
      restoreFetch();
    }
    // Same-method is enforced before anything is asked of the relayer.
    expect(grantRequests).toHaveLength(0);
  });
}
