import { expect, test } from '@playwright/test';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  burnThresholdEd25519ClientPresignWasm,
  computeThresholdEd25519DelegateSigningDigestWasm,
  computeThresholdEd25519Nep413SigningDigestWasm,
  createThresholdEd25519ClientPresignFromMaterialHandleWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  deleteThresholdEd25519SealedWorkerMaterialNearSignerWasm,
  prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm,
  prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm,
  prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm,
  prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm,
  prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorizationNearSignerWasm,
  createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm,
  signThresholdEd25519ClientPresignFromMaterialHandleWasm,
  readThresholdEd25519SealedWorkerMaterialNearSignerWasm,
  restoreThresholdEd25519WorkerMaterialNearSignerWasm,
  storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm,
} from '../../packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm';
import {
  NearSignerWorkerCustomRequestType,
  type DelegatePayload,
  type ThresholdEd25519WorkerMaterialBinding,
  type ThresholdEd25519WorkerMaterialSessionBinding,
} from '../../packages/sdk-web/src/core/types/signer-worker';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';
import { digestRouterAbEd25519WorkerMaterialSessionBinding } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssMaterialBinding';

function recordingWorkerCtx(result: unknown, calls: unknown[]): WorkerOperationContext {
  return {
    requestWorkerOperation: async (args) => {
      calls.push(args);
      return result as never;
    },
  };
}

function sampleMaterialBinding(): ThresholdEd25519WorkerMaterialBinding {
  return {
    kind: 'ed25519_worker_material_binding_v1',
    curve: 'ed25519',
    protocol: 'router_ab_normal_signing',
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    signingRootId: 'root',
    signingRootVersion: 'v1',
    relayerKeyId: 'ed25519:relayer',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
    clientVerifyingShareB64u: 'client-verifying-share',
    materialFormatVersion: 'ed25519_worker_material_v1',
    materialKeyId: 'material-key-id',
    createdAtMs: 1_700_000_000_000,
  };
}

function sampleSessionBinding(): ThresholdEd25519WorkerMaterialSessionBinding {
  return {
    kind: 'ed25519_worker_material_session_binding_v1',
    materialBindingDigest: 'binding-digest',
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    thresholdSessionId: 'threshold-session',
    signingGrantId: 'grant',
    signingRootId: 'root',
    signingRootVersion: 'v1',
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'env',
      signingRootVersion: 'v1',
    },
    relayerKeyId: 'ed25519:relayer',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
    signingWorkerId: 'worker',
    expiresAtMs: 1_700_000_000_000,
  };
}

test.describe('threshold Ed25519 near signer WASM wrappers', () => {
  test('stores worker material from HSS output through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm({
      evaluatorDriverStateB64u: 'evaluator-state',
      clientOutputMessageB64u: 'client-output',
      clientOutputMaskHandle: 'mask-handle',
      expectedContextBindingB64u: 'context-binding',
      signerSlot: 1,
      signingRootId: 'root',
      signingRootVersion: 'v1',
      nearAccountId: 'alice.testnet',
      relayerKeyId: 'ed25519:relayer',
      keyVersion: 'threshold-ed25519-hss-v1',
      participantIds: [1, 2],
      createdAtMs: 1_700_000_000_000,
      sealAuthorization: {
        kind: 'passkey_prf_material_seal_authorization_handle_v1',
        handle: 'seal-handle',
        rpId: 'example.com',
        credentialIdB64u: 'credential',
        materialKeyId: 'material-key-id',
        expiresAtMs: 1_700_000_000_000,
      },
      workerCtx: recordingWorkerCtx(
        {
          ok: true,
          materialHandle: 'material-handle',
          materialBindingDigest: 'binding-digest',
          sealedWorkerMaterialRef: 'ed25519-worker-material-v1:binding-digest',
          sealedWorkerMaterialB64u: 'sealed-worker-material',
          clientVerifyingShareB64u: 'client-verifying-share',
          materialFormatVersion: 'ed25519_worker_material_v1',
          materialKeyId: 'material-key-id',
          signerSlot: 1,
          keyVersion: 'threshold-ed25519-hss-v1',
        },
        calls,
      ),
    });

    expect(result).toEqual({
      ok: true,
      materialHandle: 'material-handle',
      materialBindingDigest: 'binding-digest',
      sealedWorkerMaterialRef: 'ed25519-worker-material-v1:binding-digest',
      sealedWorkerMaterialB64u: 'sealed-worker-material',
      clientVerifyingShareB64u: 'client-verifying-share',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: 'material-key-id',
      signerSlot: 1,
      keyVersion: 'threshold-ed25519-hss-v1',
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput,
        payload: {
          evaluatorDriverStateB64u: 'evaluator-state',
          clientOutputMessageB64u: 'client-output',
          clientOutputMask: {
            kind: 'rust_owned_mask_handle_v1',
            clientOutputMaskHandle: 'mask-handle',
          },
          expectedContextBindingB64u: 'context-binding',
          signerSlot: 1,
          keyVersion: 'threshold-ed25519-hss-v1',
          sealAuthorization: {
            kind: 'passkey_prf_material_seal_authorization_handle_v1',
            handle: 'seal-handle',
            materialKeyId: 'material-key-id',
          },
        },
      },
    });
  });

  test('prepares one-use HSS client output mask handles through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm({
      request: {
        signingRootId: 'root',
        nearAccountId: 'alice.testnet',
        keyPurpose: 'near-ed25519-signing',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
        derivationVersion: 1,
        contextBindingB64u: 'context-binding',
        operation: 'registration',
        relayerKeyId: 'ed25519:relayer',
        clientRecoverableSecretB64u: 'recoverable-secret',
        expiresAtMs: 0,
      },
      workerCtx: recordingWorkerCtx(
        {
          ok: true,
          clientOutputMaskHandle: 'mask-handle',
          contextBindingB64u: 'context-binding',
          expiresAtMs: 1_700_000_060_000,
          remainingUses: 1,
        },
        calls,
      ),
    });

    expect(result).toMatchObject({
      ok: true,
      clientOutputMaskHandle: 'mask-handle',
      remainingUses: 1,
    });
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareHssClientOutputMaskHandle,
        payload: {
          contextBindingB64u: 'context-binding',
          clientRecoverableSecretB64u: 'recoverable-secret',
        },
      },
    });
  });

  test('prepares materialKeyId-scoped seal authorization handles through the near signer worker', async () => {
    const passkeyCalls: unknown[] = [];
    const passkey =
      await prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm({
        request: {
          bindingInput: {
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            signingRootId: 'root',
            signingRootVersion: 'v1',
            relayerKeyId: 'ed25519:relayer',
            keyVersion: 'threshold-ed25519-hss-v1',
            participantIds: [1, 2],
            createdAtMs: 1_700_000_000_000,
          },
          rpId: 'example.com',
          credentialIdB64u: 'credential',
          prfFirstBytes: Uint8Array.from({ length: 32 }, (_, index) => index),
          expiresAtMs: 1_700_000_000_000,
        },
        workerCtx: recordingWorkerCtx(
          {
            ok: true,
            materialKeyId: 'material-key-id',
            sealAuthorization: {
              kind: 'passkey_prf_material_seal_authorization_handle_v1',
              handle: 'seal-handle',
              rpId: 'example.com',
              credentialIdB64u: 'credential',
              materialKeyId: 'material-key-id',
              expiresAtMs: 1_700_000_000_000,
            },
            remainingUses: 1,
          },
          passkeyCalls,
        ),
      });

    const recoveryCalls: unknown[] = [];
    const recovery =
      await prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm({
        request: {
          bindingInput: {
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            signingRootId: 'root',
            signingRootVersion: 'v1',
            relayerKeyId: 'ed25519:relayer',
            keyVersion: 'threshold-ed25519-hss-v1',
            participantIds: [1, 2],
            createdAtMs: 1_700_000_000_000,
          },
          authSubjectId: 'subject',
          recoveryCodeBindingDigest: 'recovery-binding',
          recoveryCodeSecret32: Uint8Array.from({ length: 32 }, (_, index) => 31 - index),
          expiresAtMs: 1_700_000_000_000,
        },
        workerCtx: recordingWorkerCtx(
          {
            ok: true,
            materialKeyId: 'material-key-id',
            sealAuthorization: {
              kind: 'recovery_code_material_seal_authorization_handle_v1',
              handle: 'recovery-seal-handle',
              authSubjectId: 'subject',
              recoveryCodeBindingDigest: 'recovery-binding',
              materialKeyId: 'material-key-id',
              expiresAtMs: 1_700_000_000_000,
            },
            remainingUses: 1,
          },
          recoveryCalls,
        ),
      });

    expect(passkey.sealAuthorization).toMatchObject({
      handle: 'seal-handle',
      materialKeyId: 'material-key-id',
    });
    expect(recovery.sealAuthorization).toMatchObject({
      handle: 'recovery-seal-handle',
      materialKeyId: 'material-key-id',
    });
    expect(passkeyCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization,
      },
    });
    expect(recoveryCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization,
      },
    });
  });

  test('prepares credential-scoped unseal authorization handles through the near signer worker', async () => {
    const passkeyCalls: unknown[] = [];
    const passkey =
      await prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm({
        request: {
          materialBindingDigest: 'binding-digest',
          rpId: 'example.com',
          credentialIdB64u: 'credential',
          prfFirstBytes: Uint8Array.from({ length: 32 }, (_, index) => index),
          expiresAtMs: 1_700_000_000_000,
        },
        workerCtx: recordingWorkerCtx(
          {
            ok: true,
            unsealAuthorization: {
              kind: 'passkey_prf_material_authorization_handle_v1',
              handle: 'passkey-unseal-handle',
              purpose: 'unseal',
              rpId: 'example.com',
              credentialIdB64u: 'credential',
              materialBindingDigest: 'binding-digest',
              expiresAtMs: 1_700_000_000_000,
            },
            remainingUses: 1,
          },
          passkeyCalls,
        ),
      });

    const recoveryCalls: unknown[] = [];
    const recovery =
      await prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorizationNearSignerWasm({
        request: {
          materialBindingDigest: 'binding-digest',
          authSubjectId: 'subject',
          recoveryCodeBindingDigest: 'recovery-binding',
          recoveryCodeSecret32: Uint8Array.from({ length: 32 }, (_, index) => 31 - index),
          expiresAtMs: 1_700_000_000_000,
        },
        workerCtx: recordingWorkerCtx(
          {
            ok: true,
            unsealAuthorization: {
              kind: 'recovery_code_material_authorization_handle_v1',
              handle: 'unseal-handle',
              purpose: 'unseal',
              authSubjectId: 'subject',
              recoveryCodeBindingDigest: 'recovery-binding',
              materialBindingDigest: 'binding-digest',
              expiresAtMs: 1_700_000_000_000,
            },
            remainingUses: 1,
          },
          recoveryCalls,
        ),
      });

    expect(passkey.unsealAuthorization).toMatchObject({
      handle: 'passkey-unseal-handle',
      purpose: 'unseal',
    });
    expect(recovery.unsealAuthorization).toMatchObject({
      handle: 'unseal-handle',
      purpose: 'unseal',
    });
    expect(passkeyCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization,
      },
    });
    expect(recoveryCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization,
      },
    });
  });

  test('returns typed material failures from restore and sealed storage wrappers', async () => {
    const storeCalls: unknown[] = [];
    const storeFailure = {
      ok: false,
      code: 'material_seal_authorization_required',
      message: 'material_seal_authorization_required: seal handle missing',
    } as const;
    const stored = await storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm({
      evaluatorDriverStateB64u: 'evaluator-state',
      clientOutputMessageB64u: 'client-output',
      clientOutputMaskHandle: 'mask-handle',
      expectedContextBindingB64u: 'context-binding',
      signerSlot: 1,
      signingRootId: 'root',
      signingRootVersion: 'v1',
      nearAccountId: 'alice.testnet',
      relayerKeyId: 'ed25519:relayer',
      keyVersion: 'threshold-ed25519-hss-v1',
      participantIds: [1, 2],
      createdAtMs: 1_700_000_000_000,
      sealAuthorization: {
        kind: 'passkey_prf_material_seal_authorization_handle_v1',
        handle: 'missing-seal-handle',
        rpId: 'example.com',
        credentialIdB64u: 'credential',
        materialKeyId: 'material-key-id',
        expiresAtMs: 1_700_000_000_000,
      },
      workerCtx: recordingWorkerCtx(storeFailure, storeCalls),
    });

    const restoreCalls: unknown[] = [];
    const restoreFailure = {
      ok: false,
      code: 'material_unseal_authorization_required',
      message: 'material_unseal_authorization_required: unseal handle missing',
    } as const;
    const restore = await restoreThresholdEd25519WorkerMaterialNearSignerWasm({
      request: {
        kind: 'ed25519_restore_worker_material_v1',
        sealedMaterial: {
          kind: 'storage_ref',
          sealedWorkerMaterialRef: 'ed25519-worker-material-v1:binding-digest',
        },
        expectedMaterialBinding: { materialBindingDigest: 'binding-digest' },
        unsealAuthorization: {
          kind: 'passkey_prf_material_authorization_handle_v1',
          handle: 'claim-handle',
          purpose: 'unseal',
          rpId: 'example.com',
          credentialIdB64u: 'credential',
          materialBindingDigest: 'binding-digest',
          expiresAtMs: 1_700_000_000_000,
        },
      } as never,
      workerCtx: recordingWorkerCtx(restoreFailure, restoreCalls),
    });

    const readCalls: unknown[] = [];
    const readFailure = {
      ok: false,
      code: 'material_restore_required',
      message: 'material_restore_required: sealed ref missing',
    } as const;
    const read = await readThresholdEd25519SealedWorkerMaterialNearSignerWasm({
      request: {
        kind: 'read_threshold_ed25519_sealed_worker_material_v1',
        sealedWorkerMaterialRef: 'ed25519-worker-material-v1:binding-digest',
        expectedMaterialBindingDigest: 'binding-digest',
      },
      workerCtx: recordingWorkerCtx(readFailure, readCalls),
    });

    const corruptReadCalls: unknown[] = [];
    const corruptReadFailure = {
      ok: false,
      code: 'material_corrupt',
      message: 'material_corrupt: sealed artifact could not be decoded',
    } as const;
    const corruptRead = await readThresholdEd25519SealedWorkerMaterialNearSignerWasm({
      request: {
        kind: 'read_threshold_ed25519_sealed_worker_material_v1',
        sealedWorkerMaterialRef: 'ed25519-worker-material-v1:binding-digest',
        expectedMaterialBindingDigest: 'binding-digest',
      },
      workerCtx: recordingWorkerCtx(corruptReadFailure, corruptReadCalls),
    });

    const deleteCalls: unknown[] = [];
    const deleteFailure = {
      ok: false,
      code: 'material_scope_mismatch',
      message: 'material_scope_mismatch: sealed material ref does not match binding digest',
    } as const;
    const deleted = await deleteThresholdEd25519SealedWorkerMaterialNearSignerWasm({
      request: {
        kind: 'delete_threshold_ed25519_sealed_worker_material_v1',
        sealedWorkerMaterialRef: 'ed25519-worker-material-v1:wrong-digest',
        expectedMaterialBindingDigest: 'binding-digest',
      },
      workerCtx: recordingWorkerCtx(deleteFailure, deleteCalls),
    });

    expect(stored).toEqual(storeFailure);
    expect(restore).toEqual(restoreFailure);
    expect(read).toEqual(readFailure);
    expect(corruptRead).toEqual(corruptReadFailure);
    expect(deleted).toEqual(deleteFailure);
    expect(storeCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput,
      },
    });
    expect(restoreCalls[0]).toMatchObject({
      request: { type: NearSignerWorkerCustomRequestType.ThresholdEd25519RestoreWorkerMaterial },
    });
    expect(readCalls[0]).toMatchObject({
      request: { type: NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial },
    });
    expect(corruptReadCalls[0]).toMatchObject({
      request: { type: NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial },
    });
    expect(deleteCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519DeleteSealedWorkerMaterial,
      },
    });
  });

  test('creates client presign material from a near-signer worker material handle', async () => {
    const calls: unknown[] = [];
    const expectedSessionBinding = sampleSessionBinding();
    const expectedSessionBindingDigest =
      await digestRouterAbEd25519WorkerMaterialSessionBinding(expectedSessionBinding);
    const result = await createThresholdEd25519ClientPresignFromMaterialHandleWasm({
      sessionId: 'threshold-session',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      materialHandle: 'material-handle',
      expectedMaterialBinding: sampleMaterialBinding(),
      expectedSessionBinding,
      groupPublicKey: 'ed25519:group',
      workerCtx: recordingWorkerCtx(
        {
          clientNonceHandleB64u: 'nonce-handle',
          clientVerifyingShareB64u: 'client-verifying-share',
          clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
        },
        calls,
      ),
    });

    expect(result).toEqual({
      clientNonceHandleB64u: 'nonce-handle',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        sessionId: 'threshold-session',
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreateFromMaterialHandle,
        payload: {
          clientParticipantId: 1,
          relayerParticipantId: 2,
          materialHandle: 'material-handle',
          expectedMaterialBinding: sampleMaterialBinding(),
          expectedSessionBinding,
          expectedSessionBindingDigest,
          groupPublicKey: 'ed25519:group',
        },
      },
    });
  });

  test('signs a reserved client presign from a near-signer worker material handle', async () => {
    const calls: unknown[] = [];
    const expectedSessionBinding = sampleSessionBinding();
    const expectedSessionBindingDigest =
      await digestRouterAbEd25519WorkerMaterialSessionBinding(expectedSessionBinding);
    const result = await signThresholdEd25519ClientPresignFromMaterialHandleWasm({
      sessionId: 'threshold-session',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      materialHandle: 'material-handle',
      expectedMaterialBinding: sampleMaterialBinding(),
      expectedSessionBinding,
      groupPublicKey: 'ed25519:group',
      signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      clientNonceHandleB64u: 'nonce-handle',
      clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
      relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
      workerCtx: recordingWorkerCtx({ clientSignatureShareB64u: 'client-share' }, calls),
    });

    expect(result).toEqual({ clientSignatureShareB64u: 'client-share' });
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSignFromMaterialHandle,
        payload: {
          materialHandle: 'material-handle',
          expectedMaterialBinding: sampleMaterialBinding(),
          expectedSessionBinding,
          expectedSessionBindingDigest,
          signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          clientNonceHandleB64u: 'nonce-handle',
        },
      },
    });
  });

  test('rejects material-backed signing when envelope session id differs from session binding', async () => {
    const calls: unknown[] = [];
    const expectedSessionBinding = sampleSessionBinding();
    const mismatch = /sessionId mismatch/;

    await expect(
      createThresholdEd25519ClientPresignFromMaterialHandleWasm({
        sessionId: 'wrong-threshold-session',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        materialHandle: 'material-handle',
        expectedMaterialBinding: sampleMaterialBinding(),
        expectedSessionBinding,
        groupPublicKey: 'ed25519:group',
        workerCtx: recordingWorkerCtx({}, calls),
      }),
    ).rejects.toThrow(mismatch);

    await expect(
      signThresholdEd25519ClientPresignFromMaterialHandleWasm({
        sessionId: 'wrong-threshold-session',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        materialHandle: 'material-handle',
        expectedMaterialBinding: sampleMaterialBinding(),
        expectedSessionBinding,
        groupPublicKey: 'ed25519:group',
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        clientNonceHandleB64u: 'nonce-handle',
        clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
        relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
        workerCtx: recordingWorkerCtx({}, calls),
      }),
    ).rejects.toThrow(mismatch);

    await expect(
      createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm({
        sessionId: 'wrong-threshold-session',
        materialHandle: 'material-handle',
        expectedMaterialBinding: sampleMaterialBinding(),
        expectedSessionBinding,
        groupPublicKey: 'ed25519:group',
        serverVerifyingShareB64u: 'server-verifying-share',
        serverCommitments: { hiding: 'server-hiding', binding: 'server-binding' },
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        workerCtx: recordingWorkerCtx({}, calls),
      }),
    ).rejects.toThrow(mismatch);

    expect(calls).toHaveLength(0);
  });

  test('burns an unused client presign handle through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await burnThresholdEd25519ClientPresignWasm({
      sessionId: 'threshold-session',
      clientNonceHandleB64u: 'opaque-nonce-handle',
      workerCtx: recordingWorkerCtx({ burned: true }, calls),
    });

    expect(result).toEqual({ burned: true });
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        sessionId: 'threshold-session',
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
        payload: {
          clientNonceHandleB64u: 'opaque-nonce-handle',
        },
      },
    });
  });

  test('computes signature-only signing digests through the near signer worker', async () => {
    const nep413Calls: unknown[] = [];
    const nep413 = await computeThresholdEd25519Nep413SigningDigestWasm({
      sessionId: 'threshold-session',
      message: 'hello',
      recipient: 'wallet.example',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      state: 'state',
      workerCtx: recordingWorkerCtx({ signingDigestB64u: 'digest-nep413' }, nep413Calls),
    });
    expect(nep413).toEqual({ signingDigestB64u: 'digest-nep413' });
    expect(nep413Calls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest,
        payload: { message: 'hello', recipient: 'wallet.example', state: 'state' },
      },
    });

    const delegate: DelegatePayload = {
      senderId: 'alice.testnet',
      receiverId: 'bob.testnet',
      actions: [],
      nonce: '1',
      maxBlockHeight: '2',
      publicKey: 'ed25519:group',
    };
    const delegateCalls: unknown[] = [];
    const delegateDigest = await computeThresholdEd25519DelegateSigningDigestWasm({
      sessionId: 'threshold-session',
      delegate,
      workerCtx: recordingWorkerCtx({ signingDigestB64u: 'digest-delegate' }, delegateCalls),
    });
    expect(delegateDigest).toEqual({ signingDigestB64u: 'digest-delegate' });
    expect(delegateCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest,
        payload: { delegate },
      },
    });
  });

  test('builds and decodes NEAR transaction BORSH through the near signer worker', async () => {
    const unsignedCalls: unknown[] = [];
    const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
      sessionId: 'threshold-session',
      txSigningRequest: { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
      transactionContext: {
        nearPublicKeyStr: 'ed25519:group',
        accessKeyInfo: {} as never,
        nextNonce: '1',
        txBlockHeight: '2',
        txBlockHash: 'block-hash',
      },
      workerCtx: recordingWorkerCtx(
        [{ unsignedTransactionBorshB64u: 'unsigned-tx', signingDigestB64u: 'digest-tx' }],
        unsignedCalls,
      ),
    });
    expect(unsigned).toEqual({
      unsignedTransactionBorshB64u: 'unsigned-tx',
      signingDigestB64u: 'digest-tx',
    });
    expect(unsignedCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
        payload: {
          txSigningRequests: [
            { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
          ],
        },
      },
    });

    const decodeCalls: unknown[] = [];
    const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
      sessionId: 'threshold-session',
      signedTransactionBorshB64u: 'signed-tx',
      workerCtx: recordingWorkerCtx(
        {
          signedTransaction: {
            transaction: { signerId: 'alice.testnet' },
            signature: { keyType: 0, signatureData: [1] },
            borshBytes: [2],
          },
          transactionHash: 'tx-hash',
        },
        decodeCalls,
      ),
    });
    expect(decoded).toMatchObject({
      signedTransaction: {
        transaction: { signerId: 'alice.testnet' },
        signature: { keyType: 0, signatureData: [1] },
        borshBytes: [2],
      },
      transactionHash: 'tx-hash',
    });
    expect(decodeCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh,
        payload: { signedTransactionBorshB64u: 'signed-tx' },
      },
    });
  });
});
