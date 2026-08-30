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
  RecordingEcdsaRehydrationWorker,
  type EcdsaFixtureFactor,
} from './helpers/ecdsaOperationStepUp.fixtures';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpInactiveEcdsaMaterialRecordFixture,
  buildPasskeyInactiveEcdsaMaterialRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { resolveExactInactiveEcdsaMaterialRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { resolveExactEcdsaCapabilityRuntime } from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import { buildExactEcdsaDirectCapabilityRuntime } from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { Secp256k1Engine } from '@/core/signingEngine/flows/signEvmFamily/signers/secp256k1';
import { clearAllRouterAbEcdsaDerivationClientPresignatures } from '@/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaOnlineClientRequestType,
  EcdsaPresignClientRequestType,
} from '@/core/signingEngine/workerManager/workerTypes';

// The canonical normal-signing path at its two boundaries -- hydration and
// operation step-up. Manifest plus exact durable runtime facts resolve the material,
// the worker rehydrates it, the step-up binds the canonical challenge, and the
// grant comes back attached to the signing material. Both factors run the same
// path -- only the sealed record's auth binding differs -- which is the point
// of an auth-neutral candidate.
//
// Scope, precisely: the worker is stubbed at `requestWorkerOperation` (the
// same seam the deleted record-backed rehydration coverage used) and the
// relayer at `fetch`. Confirmation UI is outside this proof; the production
// signing orchestration still returns and verifies the exact 65-byte signature.

function inactiveRuntimeRecord(
  factor: EcdsaFixtureFactor,
  fixture: Awaited<ReturnType<typeof canonicalEcdsaSealedRuntimeFixture>>['fixture'],
) {
  return factor === 'passkey'
    ? buildPasskeyInactiveEcdsaMaterialRecordFixture({
        manifest: fixture.manifest,
      })
    : buildEmailOtpInactiveEcdsaMaterialRecordFixture({
        manifest: fixture.manifest,
      });
}

function requireInactiveRuntime(
  factor: EcdsaFixtureFactor,
  fixture: Awaited<ReturnType<typeof canonicalEcdsaSealedRuntimeFixture>>['fixture'],
  chainTarget: Awaited<
    ReturnType<typeof canonicalEcdsaSealedRuntimeFixture>
  >['runtime']['chainTarget'],
) {
  const resolution = resolveExactInactiveEcdsaMaterialRuntime({
    manifest: fixture.manifest,
    walletId: toWalletId(String(fixture.manifest.signer.walletId)),
    chainTarget,
    authMethod: factor,
    inactiveRecords: [inactiveRuntimeRecord(factor, fixture)],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`${factor} inactive material did not resolve: ${resolution.reason}`);
  }
  return resolution.runtime;
}

for (const factor of ['passkey', 'email_otp'] as const) {
  test(`durable ${factor} capability pairs with an exact active session without sealed state`, async () => {
    const { fixture, runtime: sealedRuntime } = await canonicalEcdsaSealedRuntimeFixture(factor);
    const capabilityRuntime = await resolveExactEcdsaCapabilityRuntime({
      manifest: fixture.manifest,
      chainTarget: sealedRuntime.chainTarget,
      relayerUrl: sealedRuntime.relayerUrl,
    });
    if (capabilityRuntime.kind !== 'resolved') {
      throw new Error(`${factor} durable capability did not resolve: ${capabilityRuntime.reason}`);
    }
    const walletSessionId = parseWalletSessionId(`wallet-session:direct-${factor}`);
    const quotaId = parseMpcWalletSigningQuotaId(`quota:direct-${factor}`);
    if (!walletSessionId.ok || !quotaId.ok) throw new Error('Direct session fixture is invalid');

    const runtime = buildExactEcdsaDirectCapabilityRuntime({
      runtime: capabilityRuntime.runtime,
      authority: fixture.authority,
      status: {
        status: 'active',
        walletSessionId: walletSessionId.value,
        quotaId: quotaId.value,
        remainingUses: sealedRuntime.remainingUses,
        expiresAtMs: sealedRuntime.expiresAtMs,
      },
    });

    expect(runtime.kind).toBe('exact_ecdsa_direct_capability_runtime_v1');
    expect(runtime.sealedRecord).toBeUndefined();
    expect(runtime.authBinding.kind).toBe(factor);
    expect(runtime.materialActivation).toEqual(fixture.manifest.activation.materialActivation);
  });

  test(`inactive ${factor} material reaches canonical worker hydration`, async () => {
    const {
      fixture,
      runtime: activeRuntime,
      worker,
    } = await canonicalEcdsaSealedRuntimeFixture(factor);
    const { capability, manifest } = fixture;
    const runtime = requireInactiveRuntime(factor, fixture, activeRuntime.chainTarget);
    expect(runtime.authBinding.kind).toBe(factor);

    const resolution = await resolveHydratedSecp256k1SigningMaterial({
      capability,
      runtime,
      chainTarget: runtime.chainTarget,
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

    expect(resolution.material.chainTarget).toEqual(runtime.chainTarget);

    // Hydrated material is auth-neutral: it carries no authorization and no
    // bearer credential of its own.
    expect(resolution.material.authorization).toBeUndefined();
    expect(resolution.material.credential).toBeUndefined();
    expect(resolution.material.walletSessionJwt).toBeUndefined();
  });
}

test('inactive ECDSA hydration binds the worker and signs the exact authorized operation', async () => {
  clearAllRouterAbEcdsaDerivationClientPresignatures();
  const {
    fixture,
    runtime: activeRuntime,
    worker,
  } = await canonicalEcdsaSealedRuntimeFixture('passkey');
  const runtime = requireInactiveRuntime('passkey', fixture, activeRuntime.chainTarget);
  const hydration = await resolveHydratedSecp256k1SigningMaterial({
    capability: fixture.capability,
    runtime,
    chainTarget: runtime.chainTarget,
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
      authority: fixture.authority,
      authorization: ecdsaOperationStepUpAuthorizationFixture('passkey'),
      prepared,
      material: hydration.material,
      walletSessionToken: WALLET_SESSION_TOKEN,
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
        kind: 'ecdsaDerivationClient',
        request: expect.objectContaining({
          type: EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial,
          payload: expect.objectContaining({
            materialActivation: fixture.manifest.activation.materialActivation,
          }),
        }),
      }),
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
    chainTarget: runtime.chainTarget,
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
    chainTarget: testEcdsaChainTarget(otherChain),
    materialActivation: manifest.activation.materialActivation,
    workerCtx: worker,
  });

  expect(resolution).toMatchObject({ kind: 'unavailable', reason: 'chain_mismatch' });
  expect(worker.requests).toHaveLength(0);
});

test('canonical ECDSA material projects to a published Arc target', async () => {
  const tempoTarget = testEcdsaChainTarget('tempo');
  const arcTarget = {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 5_042_002,
    networkSlug: 'arc-testnet',
  };
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey', {
    chainTarget: tempoTarget,
    targetMemberships: [tempoTarget, arcTarget],
  });
  const runtimeResolution = await resolveExactEcdsaCapabilityRuntime({
    manifest: fixture.manifest,
    chainTarget: arcTarget,
    relayerUrl: 'https://relayer.example.test',
  });
  if (runtimeResolution.kind !== 'resolved') {
    throw new Error(`Arc capability runtime did not resolve: ${runtimeResolution.reason}`);
  }
  const worker = new RecordingEcdsaRehydrationWorker(fixture.manifest);
  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability: fixture.capability,
    runtime: runtimeResolution.runtime,
    chainTarget: arcTarget,
    materialActivation: fixture.manifest.activation.materialActivation,
    workerCtx: worker,
  });

  if (resolution.kind !== 'ready') {
    throw new Error(`Arc hydration was unavailable: ${resolution.reason}`);
  }
  expect(resolution.material.chainTarget).toEqual(arcTarget);
  expect(worker.requests).toHaveLength(1);
});

// The rest of the operating path: the material hydrated above is what the
// operation step-up is prepared against, and the grant that comes back is
// attached to the signing material for exactly one operation. The relayer is
// stubbed at `fetch` -- the only network seam on this path -- so everything
// from preparation through grant attachment is production code.

const OPERATION_ID = 'operating-path-operation-1';
const WALLET_SESSION_TOKEN = 'wallet-session-operation-credential';
const EVIDENCE_SET_DIGEST = Buffer.alloc(32, 42).toString('base64url');
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
        kind: 'verified_step_up',
        operation_kind: 'evm.sign_transaction',
        authorization: {
          kind: 'operation_step_up',
          evidence_set_digest: EVIDENCE_SET_DIGEST,
          unseal: { kind: 'not_requested' },
        },
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
        authority,
        authorization: ecdsaOperationStepUpAuthorizationFixture(factor),
        prepared,
        material,
        walletSessionToken: WALLET_SESSION_TOKEN,
      });
    } finally {
      restoreFetch();
    }

    // Exactly one grant, for exactly this operation.
    expect(grantRequests).toHaveLength(1);
    expect(ready.authorization).toEqual({ kind: 'operation_step_up' });
    expect(ready.operationStepUpPreparation).toEqual(prepared.operation);
    expect(String(ready.signerSession.materialActivation.activationId)).toBe(
      String(material.materialActivation.activationId),
    );

    // No reusable Wallet Session was created or read anywhere on this path.
    expect(ready.singleUseEmailOtpSession).toBe(false);
    expect(ready.credential).toEqual({
      kind: 'operation_step_up',
      walletSessionToken: WALLET_SESSION_TOKEN,
    });
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
          authority,
          // The proof is built for the wrong factor for this capability.
          authorization: ecdsaOperationStepUpAuthorizationFixture(otherFactor),
          prepared,
          material,
          walletSessionToken: WALLET_SESSION_TOKEN,
        }),
      ).rejects.toThrow(/exact (passkey|Email OTP) authority/);
    } finally {
      restoreFetch();
    }
    // Same-method is enforced before anything is asked of the relayer.
    expect(grantRequests).toHaveLength(0);
  });
}
