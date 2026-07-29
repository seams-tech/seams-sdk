import { expect, test } from '@playwright/test';
import { resolveHydratedSecp256k1SigningMaterial } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { parseEcdsaRoleLocalWorkerHandle } from '@/core/signingEngine/session/keyMaterialBrands';
import { EcdsaDerivationClientCustomResponseType } from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSigningCapability';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  authorizeEvmFamilyEcdsaOperationStepUp,
  prepareEvmFamilyEcdsaOperationStepUp,
} from '@/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import { computeRouterAbEcdsaOperationStepUpChallengeB64u } from '@shared/utils/routerAbEcdsaDerivation';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { type WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { HydratedEcdsaSignerMaterial } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpEcdsaSealedRuntimeRecordFixture,
  buildPasskeyEcdsaSealedRuntimeRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

// The canonical normal-signing operating path, end to end at the hydration
// boundary: manifest plus exact sealed runtime resolve the material, the worker
// rehydrates it, and the returned signer material is bound to that exact
// activation. Both factors run the same path -- only the sealed record's auth
// binding differs -- which is the point of an auth-neutral candidate.
//
// The worker is stubbed at `requestWorkerOperation`, the same seam the deleted
// record-backed rehydration coverage used. Everything above it is production
// code.

type Factor = 'passkey' | 'email_otp';

async function sealedRuntimeFor(factor: Factor) {
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture(factor);
  const { capability, manifest } = fixture;
  const record =
    factor === 'passkey'
      ? buildPasskeyEcdsaSealedRuntimeRecordFixture({ manifest })
      : buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`${factor} sealed runtime did not resolve: ${resolution.reason}`);
  }
  return { authority: fixture.authority, capability, manifest, runtime: resolution.runtime };
}

/** Records every worker request so a test can assert the worker was never
 * reached when an earlier gate should have failed closed. */
function rehydratingWorker(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  requests: unknown[];
}): WorkerOperationContext {
  const durable = args.manifest.durableMaterial;
  return {
    requestWorkerOperation: async (request) => {
      args.requests.push(request);
      return {
        type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          kind: 'ecdsa_role_local_signing_material_opened_v1',
          ok: true,
          liveHandle: parseEcdsaRoleLocalWorkerHandle({
            kind: 'ecdsa_role_local_worker_handle_v1',
            materialHandle: `${String(durable.durableMaterialRef)}:live`,
            bindingDigest: String(durable.bindingDigest),
            durableMaterialRef: durable.durableMaterialRef,
          }),
          materialRef: {
            kind: 'ecdsa_role_local_persisted_material_ref_v1',
            durableMaterialRef: durable.durableMaterialRef,
            bindingDigest: durable.bindingDigest,
            materialActivation: durable.materialActivation,
          },
        },
      } as never;
    },
  } as WorkerOperationContext;
}

for (const factor of ['passkey', 'email_otp'] as const) {
  test(`canonical ${factor} normal signing reaches worker binding`, async () => {
    const { capability, manifest, runtime } = await sealedRuntimeFor(factor);
    expect(runtime.authBinding.kind).toBe(factor);

    const requests: unknown[] = [];
    const resolution = await resolveHydratedSecp256k1SigningMaterial({
      capability,
      runtime,
      requestLabel: runtime.chainTarget.kind,
      materialActivation: manifest.activation.materialActivation,
      workerCtx: rehydratingWorker({ manifest, requests }),
    });

    if (resolution.kind !== 'ready') {
      throw new Error(`${factor} hydration was unavailable: ${resolution.reason}`);
    }

    // The worker was actually reached, and the material it returned is bound to
    // the exact activation the manifest names.
    expect(requests.length).toBeGreaterThan(0);
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

test('activation mismatch fails before the worker is reached', async () => {
  const { capability, manifest, runtime } = await sealedRuntimeFor('passkey');
  const requests: unknown[] = [];

  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    requestLabel: runtime.chainTarget.kind,
    // A different activation than the manifest names.
    materialActivation: buildMpcMaterialActivationRefFixture(
      'operating-path-other-activation',
      String(manifest.signer.walletId),
    ),
    workerCtx: rehydratingWorker({ manifest, requests }),
  });

  expect(resolution).toMatchObject({
    kind: 'unavailable',
    reason: 'material_activation_mismatch',
  });
  // The gate is before hydration: no worker request was issued, so no material
  // was opened for an activation the manifest does not name.
  expect(requests).toHaveLength(0);
});

test('a chain the runtime does not serve fails before the worker is reached', async () => {
  const { capability, manifest, runtime } = await sealedRuntimeFor('email_otp');
  const requests: unknown[] = [];
  const otherChain = runtime.chainTarget.kind === 'evm' ? 'tempo' : 'evm';

  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    requestLabel: otherChain,
    materialActivation: manifest.activation.materialActivation,
    workerCtx: rehydratingWorker({ manifest, requests }),
  });

  expect(resolution).toMatchObject({ kind: 'unavailable', reason: 'chain_mismatch' });
  expect(requests).toHaveLength(0);
});

// The rest of the operating path: the material hydrated above is what the
// operation step-up is prepared against, and the grant that comes back is
// attached to the signing material for exactly one operation. The relayer is
// stubbed at `fetch` -- the only network seam on this path -- so everything
// from preparation through grant attachment is production code.

const OPERATION_ID = 'operating-path-operation-1';
const GRANT_ID = 'operating-path-grant-1';

function b64u(seed: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(seed)).toString('base64url');
}

const operationDigests = {
  laneDigest: parseDigestB64u(b64u(11, 32)),
  intentDigest: parseDigestB64u(b64u(12, 32)),
  displayDigest: parseDigestB64u(b64u(13, 32)),
};

async function hydratedMaterialFor(factor: Factor): Promise<{
  material: HydratedEcdsaSignerMaterial;
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  authority: WalletAuthAuthority;
}> {
  const { authority, capability, manifest, runtime } = await sealedRuntimeFor(factor);
  const resolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    requestLabel: runtime.chainTarget.kind,
    materialActivation: manifest.activation.materialActivation,
    workerCtx: rehydratingWorker({ manifest, requests: [] }),
  });
  if (resolution.kind !== 'ready') {
    throw new Error(`${factor} hydration was unavailable: ${resolution.reason}`);
  }
  return {
    material: resolution.material,
    capability,
    authority,
  };
}

/** Stands in for the relayer's operation step-up grant endpoint. Records every
 * request so a test can assert exactly one grant was issued. */
function stubGrantEndpoint(requests: unknown[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
    requests.push(JSON.parse(String(init?.body || '{}')));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        ok: true,
        kind: 'operation_step_up',
        authorization: { kind: 'operation_step_up', grant_id: GRANT_ID },
        authorization_session_id: 'operating-path-auth-session-1',
        expires_at_ms: Date.now() + 5 * 60_000,
      }),
    };
  }) as unknown as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

function stepUpAuthorizationFor(factor: Factor) {
  return factor === 'passkey'
    ? ({
        kind: 'passkey' as const,
        signingAuthPlan: { kind: 'passkeyReauth' as const, method: 'passkey' as const },
        credential: {
          id: 'credential-passkey-fixture',
          rawId: 'raw-id',
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: 'client-data',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
          },
        },
      } as never)
    : ({
        kind: 'email_otp' as const,
        signingAuthPlan: { kind: 'emailOtpReauth' as const, method: 'email_otp' as const },
        challengeId: 'operating-path-otp-challenge',
        otpCode: '123456',
      } as never);
}

for (const factor of ['passkey', 'email_otp'] as const) {
  test(`canonical ${factor} material authorizes one operation by step-up`, async () => {
    const { material, capability, authority } = await hydratedMaterialFor(factor);

    const prepared = await prepareEvmFamilyEcdsaOperationStepUp({
      operation: {
        intent: { operationId: OPERATION_ID } as never,
        authPlan: { kind: 'passkeyReauth', method: 'passkey' } as never,
      },
      operationDigests,
      material,
      evmFamilySigningKeySlotId: capability.material.publicFacts.evmFamilySigningKeySlotId,
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
        authorization: stepUpAuthorizationFor(factor),
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
    const { material, authority } = await hydratedMaterialFor(factor);
    const otherFactor: Factor = factor === 'passkey' ? 'email_otp' : 'passkey';
    const grantRequests: unknown[] = [];
    const restoreFetch = stubGrantEndpoint(grantRequests);
    try {
      await expect(
        authorizeEvmFamilyEcdsaOperationStepUp({
          relayerUrl: 'https://relayer.example.test',
          sessionAuth: { kind: 'app_session_cookie' },
          authority,
          // The proof is built for the wrong factor for this capability.
          authorization: stepUpAuthorizationFor(otherFactor),
          prepared: {
            operation: {} as never,
            challengeB64u: 'unused',
          },
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
