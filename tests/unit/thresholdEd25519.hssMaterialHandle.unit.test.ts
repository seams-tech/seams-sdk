import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  NearSignerWorkerCustomRequestType,
} from '@/core/types/signer-worker';
import { requireThresholdEd25519WorkerMaterialHandle } from '@/core/signingEngine/threshold/ed25519/workerMaterialHandle';
import {
  buildRouterAbEd25519WorkerMaterialBinding,
  buildRouterAbEd25519WorkerMaterialSessionBinding,
} from '@/core/signingEngine/threshold/ed25519/workerMaterialBinding';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519HssKeyVersion,
  parseEd25519RelayerKeyId,
  parseEd25519WorkerMaterialHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';

async function digestCanonicalJsonB64u(input: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

test.describe('threshold Ed25519 HSS material handles', () => {
  test('near signer stores worker material in Rust without a TypeScript raw-material map', () => {
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

    expect(source).toContain('threshold_ed25519_worker_material_store_from_hss_output');
    expect(source).not.toContain('thresholdEd25519HssMaterialByHandle');
    expect(source).not.toContain('StoredEd25519HssMaterial');
    expect(source).not.toContain('threshold_ed25519_hss_verifying_share_from_signing_share');
  });

  test('requires loaded near-signer worker handles without PRF reconstruction', async () => {
    const workspaceRoot = process.cwd().endsWith(`${path.sep}tests`)
      ? path.resolve(process.cwd(), '..')
      : process.cwd();
    const materialHandleSource = readFileSync(
      path.join(
        workspaceRoot,
        'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts',
      ),
      'utf8',
    );
    const materialHandle = parseEd25519WorkerMaterialHandle(
      'ed25519-worker-material:tsess:test-binding',
    );
    const clientVerifyingShareB64u = parseEd25519ClientVerifyingShareB64u(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    );
    const relayerKeyId = parseEd25519RelayerKeyId('ed25519:relayer');
    const thresholdKeyMaterial = {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
      kind: 'threshold_ed25519_v1',
      publicKey: 'ed25519:group',
      relayerKeyId: 'ed25519:relayer',
      keyVersion: 'threshold-ed25519-hss-v1',
      participants: [
        { id: 1, role: 'client' },
        { id: 2, role: 'relayer', relayerKeyId: 'ed25519:relayer' },
      ],
      timestamp: 1_700_000_000_000,
    } satisfies ThresholdEd25519KeyMaterial;
    const material = await buildRouterAbEd25519WorkerMaterialBinding({
      nearAccountId: 'alice.testnet',
      signerSlot: thresholdKeyMaterial.signerSlot,
      signingRootId: 'root',
      signingRootVersion: 'v1',
      relayerKeyId,
      ed25519HssKeyVersion: parseEd25519HssKeyVersion(thresholdKeyMaterial.keyVersion),
      participantIds: [1, 2],
      clientVerifyingShareB64u,
      createdAtMs: thresholdKeyMaterial.timestamp,
    });
    const bindingDigest = material.materialBindingDigest;
    const calls: Array<{ kind: string; type: unknown }> = [];

    const result = await requireThresholdEd25519WorkerMaterialHandle({
      ctx: {
        requestWorkerOperation: async ({ kind, request }) => {
          calls.push({ kind, type: request.type });
          if (
            kind === 'nearSigner' &&
            request.type === NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial
          ) {
            return {
              materialHandle,
              bindingDigest,
              clientVerifyingShareB64u,
            } as never;
          }
          throw new Error(`unexpected worker call ${kind}:${String(request.type)}`);
        },
      },
      thresholdSessionId: 'tsess',
      signingGrantId: 'wsess',
      existingMaterialHandle: materialHandle,
      existingMaterialBindingDigest: bindingDigest,
      existingMaterialClientVerifierB64u: clientVerifyingShareB64u,
      signingRootId: 'root',
      signingRootVersion: 'v1',
      expiresAtMs: Date.now() + 60_000,
      relayerKeyId,
      nearAccountId: 'alice.testnet',
      participantIds: [1, 2],
      signingWorkerId: 'signing-worker',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'project',
        envId: 'env',
        signingRootVersion: 'v1',
      },
      thresholdKeyMaterial,
    });

    expect(materialHandleSource).toContain('buildRouterAbEd25519SigningMaterialRef');
    expect(materialHandleSource).not.toContain('as Ed25519WorkerMaterialHandle');
    expect(result).toMatchObject({
      kind: 'router_ab_ed25519_runtime_validated_material_v1',
      materialRef: {
        materialHandle,
        bindingDigest,
        clientVerifierB64u: clientVerifyingShareB64u,
      },
      sessionBinding: {
        thresholdSessionId: 'tsess',
        signingGrantId: 'wsess',
        signingWorkerId: 'signing-worker',
      },
    });
    expect(calls).toEqual([
      {
        kind: 'nearSigner',
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial,
      },
    ]);
  });

  test('worker material digest vectors match Rust canonicalization', async () => {
    const material = await buildRouterAbEd25519WorkerMaterialBinding({
      nearAccountId: 'alice.near',
      signerSlot: 1,
      signingRootId: 'project:env',
      signingRootVersion: 'v1',
      relayerKeyId: parseEd25519RelayerKeyId('ed25519:relayer'),
      ed25519HssKeyVersion: parseEd25519HssKeyVersion('threshold-ed25519-hss-v1'),
      participantIds: [1, 2],
      clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u('clientVerifier'),
      createdAtMs: 1_700_000_000_000,
    });
    const sessionBinding = buildRouterAbEd25519WorkerMaterialSessionBinding({
      materialBindingDigest: material.materialBindingDigest,
      nearAccountId: 'alice.near',
      signerSlot: 1,
      thresholdSessionId: 'threshold-session',
      signingGrantId: 'signing-grant',
      signingRootId: 'project:env',
      signingRootVersion: 'v1',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'project',
        envId: 'env',
        signingRootVersion: 'v1',
      },
      relayerKeyId: parseEd25519RelayerKeyId('ed25519:relayer'),
      ed25519HssKeyVersion: parseEd25519HssKeyVersion('threshold-ed25519-hss-v1'),
      participantIds: [1, 2],
      signingWorkerId: 'signing-worker',
      expiresAtMs: 1_900_000_000_000,
    });
    const aad = {
      kind: 'ed25519_sealed_worker_material_aad_v1',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialBindingDigest: material.materialBindingDigest,
      binding: material.materialBinding,
      aeadAlgorithm: 'chacha20poly1305',
      kdfAlgorithm: 'hkdf_sha256',
      kdfInfo: 'seams-ed25519-worker-material-v1',
    };

    expect(alphabetizeStringify(material.materialBinding)).toBe(
      '{"clientVerifyingShareB64u":"clientVerifier","createdAtMs":1700000000000,"curve":"ed25519","keyVersion":"threshold-ed25519-hss-v1","kind":"ed25519_worker_material_binding_v1","materialFormatVersion":"ed25519_worker_material_v1","materialKeyId":"68zLDBT7vbB8YBa1ckFElOgOaTGKAF_ZgB3ExApHWEo","nearAccountId":"alice.near","participantIds":[1,2],"protocol":"router_ab_normal_signing","relayerKeyId":"ed25519:relayer","signerSlot":1,"signingRootId":"project:env","signingRootVersion":"v1"}',
    );
    expect(material.materialBinding.materialKeyId).toBe(
      '68zLDBT7vbB8YBa1ckFElOgOaTGKAF_ZgB3ExApHWEo',
    );
    expect(material.materialBindingDigest).toBe(
      'nVj1qAfSRNkAiFqo-AOhidltXdCj5rsvPiVmfxTalZY',
    );
    expect(await digestCanonicalJsonB64u(sessionBinding)).toBe(
      'SBCUK9pp4dT3AHPupQgx7MoIQ-RXq3aFKhxbucibB1o',
    );
    expect(await digestCanonicalJsonB64u(aad)).toBe(
      '2RLqwrXrAy5p30JhaSYf2ncZJJDMpBVN_-LmcSVLyw8',
    );
  });
});
