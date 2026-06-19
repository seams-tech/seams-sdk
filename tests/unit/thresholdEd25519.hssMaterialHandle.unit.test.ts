import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  HssClientCustomRequestType,
  HssClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  NearSignerWorkerCustomRequestType,
} from '@/core/types/signer-worker';
import { ensureThresholdEd25519HssSigningMaterial } from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import {
  storeRouterAbEd25519SigningMaterialHandleWasm,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';

test.describe('threshold Ed25519 HSS material handles', () => {
  test('near signer stores HSS material with role-separated verifier', () => {
    const workspaceRoot = process.cwd().endsWith(`${path.sep}tests`)
      ? path.resolve(process.cwd(), '..')
      : process.cwd();
    const source = readFileSync(
      path.join(
        workspaceRoot,
        'packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts',
      ),
      'utf8',
    );

    expect(source).toContain(
      'threshold_ed25519_role_separated_client_verifying_share_from_base_share',
    );
    expect(source).not.toContain('threshold_ed25519_hss_verifying_share_from_signing_share');
  });

  test('uses loaded worker handles before PRF reconstruction', async () => {
    const materialHandle = 'ed25519-hss-material:tsess:test-binding';
    const bindingDigest = 'test-binding';
    const clientVerifyingShareB64u = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const calls: Array<{ kind: string; type: unknown }> = [];

    const result = await ensureThresholdEd25519HssSigningMaterial({
      ctx: {
        requestWorkerOperation: async ({ kind, request }) => {
          calls.push({ kind, type: request.type });
          if (
            kind === 'hssClient' &&
            request.type === HssClientCustomRequestType.ValidateThresholdEd25519HssMaterial
          ) {
            return {
              type: HssClientCustomResponseType.ValidateThresholdEd25519HssMaterialSuccess,
              payload: {
                materialHandle,
                bindingDigest,
                clientVerifyingShareB64u,
              },
            } as never;
          }
          throw new Error(`unexpected worker call ${kind}:${String(request.type)}`);
        },
      },
      thresholdSessionId: 'tsess',
      walletSigningSessionId: 'wsess',
      existingMaterialHandle: materialHandle,
      existingMaterialBindingDigest: bindingDigest,
      existingMaterialClientVerifierB64u: clientVerifyingShareB64u,
      walletSessionJwt: 'jwt',
      signingRootId: 'root',
      signingRootVersion: 'v1',
      expiresAtMs: Date.now() + 60_000,
      relayerUrl: 'https://router.example',
      relayerKeyId: 'ed25519:relayer',
      nearAccountId: 'alice.testnet',
      keyVersion: 'threshold-ed25519-hss-v1',
      participantIds: [1, 2],
      signingWorkerId: 'signing-worker',
      prfFirstB64u: '',
    });

    expect(result).toMatchObject({
      materialHandle,
      bindingDigest,
      clientVerifyingShareB64u,
      thresholdSessionId: 'tsess',
      walletSigningSessionId: 'wsess',
      signingWorkerId: 'signing-worker',
    });
    expect(calls).toEqual([
      {
        kind: 'hssClient',
        type: HssClientCustomRequestType.ValidateThresholdEd25519HssMaterial,
      },
    ]);
  });

  test('stores Router A/B Ed25519 HSS material in both signing workers', async () => {
    const calls: Array<{ kind: string; type: unknown; payload: Record<string, unknown> }> = [];
    const result = await storeRouterAbEd25519SigningMaterialHandleWasm({
      workerCtx: {
        requestWorkerOperation: async ({ kind, request }) => {
          const payload = request.payload as Record<string, unknown>;
          calls.push({ kind, type: request.type, payload });
          if (
            kind === 'hssClient' &&
            request.type === HssClientCustomRequestType.StoreThresholdEd25519HssMaterial
          ) {
            return {
              type: HssClientCustomResponseType.StoreThresholdEd25519HssMaterialSuccess,
              payload: {
                materialHandle: payload.materialHandle,
                bindingDigest: payload.bindingDigest,
                clientVerifyingShareB64u: payload.expectedClientVerifyingShareB64u,
              },
            } as never;
          }
          if (
            kind === 'nearSigner' &&
            request.type === NearSignerWorkerCustomRequestType.ThresholdEd25519StoreHssMaterial
          ) {
            return {
              materialHandle: payload.materialHandle,
              bindingDigest: payload.bindingDigest,
              clientVerifyingShareB64u: payload.expectedClientVerifyingShareB64u,
            } as never;
          }
          throw new Error(`unexpected worker call ${kind}:${String(request.type)}`);
        },
      },
      materialCache: {
        kind: 'ed25519_hss_material_cache_v1',
        xClientBaseB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        clientVerifyingShareB64u: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      },
      thresholdSessionId: 'tsess-dual-store',
      walletSigningSessionId: 'wsess-dual-store',
      signingRootId: 'root-dual-store',
      signingRootVersion: 'v1',
      expiresAtMs: Date.now() + 60_000,
      nearAccountId: 'dual-store.testnet',
      relayerKeyId: 'ed25519:dual-store-relayer',
      participantIds: [1, 2],
      signingWorkerId: 'signing-worker',
    });

    expect(calls.map((call) => [call.kind, call.type])).toEqual([
      ['hssClient', HssClientCustomRequestType.StoreThresholdEd25519HssMaterial],
      ['nearSigner', NearSignerWorkerCustomRequestType.ThresholdEd25519StoreHssMaterial],
    ]);
    expect(calls[1].payload.materialHandle).toBe(calls[0].payload.materialHandle);
    expect(calls[1].payload.bindingDigest).toBe(calls[0].payload.bindingDigest);
    expect(calls[1].payload.expectedClientVerifyingShareB64u).toBe(
      calls[0].payload.expectedClientVerifyingShareB64u,
    );
    expect(result.materialHandle).toBe(calls[0].payload.materialHandle);
  });
});
