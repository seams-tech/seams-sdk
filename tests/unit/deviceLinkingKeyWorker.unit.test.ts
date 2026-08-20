import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { installDeviceLinkingKeyWorkerV1 } from '../../packages/wallet/src/core/signingEngine/workerManager/workers/device-linking-key.worker';
import {
  buildR102EcdsaLaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
  buildR103SealedHolderRecord,
} from './helpers/r102LaneGateway.fixtures';
import { EcdsaClientWorkerControlKind } from '../../packages/wallet/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels';

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

async function waitForResponse(scope: FakeWorkerScope): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = scope.responses.at(0);
    if (response && typeof response === 'object') return response as Record<string, unknown>;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('worker response timed out');
}

test.describe('device-linking key worker', () => {
  test('opens persisted linked holders from a fresh Email OTP factor release in the worker', async () => {
    const scope = new FakeWorkerScope();
    const openedSecrets: number[] = [];
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      openSigningMaterial(input) {
        openedSecrets.push(input.factorSecret[0] ?? 0);
        return {
          key_family: () => 'ecdsa_secp256k1',
          create_ed25519_signing_share: () => {
            throw new Error('Ed25519 signing is outside this test');
          },
          create_ecdsa_presign_session: () => {
            throw new Error('presigning is outside this test');
          },
          destroy: () => undefined,
          free: () => undefined,
        };
      },
    });
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
    const job = buildR102EcdsaLaneJob('email-otp-worker');
    if (job.authorization.kind !== 'linked_device_enrollment') {
      throw new Error('fixture job must use linked-device enrollment authorization');
    }
    const linkedDeviceEnrollmentId = job.authorization.linkedDeviceEnrollmentId;
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    const materialActivation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
    const holderRecord = buildR103SealedHolderRecord(job, protocolCommitReceipt);
    scope.send({
      id: 'open-email-otp-holder',
      request: {
        kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1',
        handleId,
        walletId,
        enrollmentId: linkedDeviceEnrollmentId,
        expectedChallengeId: challengeId,
        factorRelease: {
          kind: 'email_otp_factor_release_v1',
          challengeId,
          enrollmentId: ownerEnrollmentId,
          enrollmentSealKeyVersion,
          serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey),
          nonce12B64u: base64UrlEncode(nonce),
          ciphertextB64u: base64UrlEncode(ciphertext),
        },
        orderedChildren: [
          { job, protocolCommitReceipt, materialActivation, holderRecord },
        ],
      },
    });
    const opened = await waitForResponse(scope);
    scope.responses.shift();
    expect(opened).toMatchObject({
      ok: true,
      result: { holderSigningMaterialHandles: [{ keyFamily: 'ecdsa_secp256k1' }] },
    });
    expect(openedSecrets).toEqual([29]);

    scope.send({
      id: 'reuse-discarded-email-otp-slot',
      request: {
        kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1',
        handleId,
        walletId,
        enrollmentId: linkedDeviceEnrollmentId,
        expectedChallengeId: challengeId,
        factorRelease: {
          kind: 'email_otp_factor_release_v1',
          challengeId,
          enrollmentId: ownerEnrollmentId,
          enrollmentSealKeyVersion,
          serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey),
          nonce12B64u: base64UrlEncode(nonce),
          ciphertextB64u: base64UrlEncode(ciphertext),
        },
        orderedChildren: [
          { job, protocolCommitReceipt, materialActivation, holderRecord },
        ],
      },
    });
    const reused = await waitForResponse(scope);
    expect(reused).toMatchObject({
      ok: false,
      error: 'device-linking key handle is unknown or discarded',
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

  test('runs linked-holder ECDSA presign behind an opaque worker capability', async () => {
    const scope = new FakeWorkerScope();
    let presignSessionCreates = 0;
    let presignSessionFrees = 0;
    const installed = installDeviceLinkingKeyWorkerV1(scope, {
      openSigningMaterial() {
        return {
          key_family: () => 'ecdsa_secp256k1',
          create_ed25519_signing_share: () => {
            throw new Error('Ed25519 signing is outside this ECDSA test');
          },
          create_ecdsa_presign_session: () => {
            presignSessionCreates += 1;
            return {
              stage: () => 'triples',
              poll: () => ({
                stage: 'triples',
                event: 'none',
                outgoing: [new Uint8Array([7, 8, 9])],
              }),
              message: () => undefined,
              start_presign: () => undefined,
              presignature_big_r_33: () => {
                throw new Error('presign is not complete');
              },
              compute_signature_share: () => {
                throw new Error('presign is not complete');
              },
              free: () => {
                presignSessionFrees += 1;
              },
            };
          },
          destroy: () => undefined,
          free: () => undefined,
        };
      },
    });
    const job = buildR102EcdsaLaneJob('device-linking-holder-presign');
    if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('ECDSA fixture changed branch');
    const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
    const materialActivation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
    const holderRecord = buildR103SealedHolderRecord(job, protocolCommitReceipt);
    const factorSecret = new Uint8Array(32).fill(29).buffer;
    scope.send({
      id: 'open-ecdsa-signing-material',
      request: {
        kind: 'device_linking_holder_signing_material_open_v1',
        factorSecret,
        job,
        protocolCommitReceipt,
        materialActivation,
        holderRecord,
      },
    });
    const opened = await waitForResponse(scope);
    expect(opened).toMatchObject({
      ok: true,
      result: { keyFamily: 'ecdsa_secp256k1' },
    });
    expect(new Uint8Array(factorSecret)).toEqual(new Uint8Array(32));
    const holderHandleId = String((opened.result as Record<string, unknown>).handleId);

    const channel = new MessageChannel();
    scope.send({
      kind: EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign,
      port: channel.port1,
    });
    const response = new Promise<Record<string, unknown>>((resolve) => {
      channel.port2.onmessage = (event) => resolve(event.data as Record<string, unknown>);
      channel.port2.start();
    });
    const groupPublicKey33 = base64UrlDecode(job.thresholdPublicKey33B64u);
    channel.port2.postMessage(
      {
        kind: 'opaque_ecdsa_presign_session_init_v1',
        requestId: 'linked-presign-1',
        sessionId: 'linked-presign-session-1',
        authority: {
          kind: 'linked_holder_signing_material',
          holderHandleId,
        },
        poolIdentity: {
          poolKey: 'linked-holder-pool',
          materialActivationId: materialActivation.activationId,
          capability: materialActivation.capability,
          keyBinding: materialActivation.keyBinding,
          walletId: job.walletId,
          signingScopeB64u: digest(42),
          pairRole: 'client',
          keyEpoch: 'linked-holder-key-epoch-1',
          activationEpoch: 'linked-holder-activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1',
        },
        groupPublicKey33: groupPublicKey33.buffer,
        materialExpiresAtMs: Date.now() + 60_000,
      },
      [groupPublicKey33.buffer],
    );
    const progress = await response;
    expect(progress).toMatchObject({
      kind: 'opaque_ecdsa_presign_authority_result_v1',
      requestId: 'linked-presign-1',
      ok: true,
      result: {
        kind: 'progress',
        progress: { stage: 'triples', event: 'none' },
      },
    });
    expect(presignSessionCreates).toBe(1);
    expect(scope.responses).toHaveLength(1);
    channel.port2.close();
    await installed.close();
    expect(presignSessionFrees).toBe(1);
  });

});
