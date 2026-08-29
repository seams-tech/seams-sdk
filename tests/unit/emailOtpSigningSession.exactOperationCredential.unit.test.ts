import { expect, test } from '@playwright/test';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  walletSessionAuthorizations,
  type WalletSessionAuthorizationExactOperationCredentialReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  emailOtpEcdsaSigningSessionAuthLane,
  resolveExactEmailOtpEcdsaSigningSessionAuthority,
} from '@/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture } from './helpers/exactEvmFamilyWalletSessionAuthorization.fixtures';
import type { ExactEvmFamilyWalletSessionAuthorization } from '@/core/signingEngine/session/material/ecdsaSigningCapability';

class ExactSessionReadHarness {
  read: WalletSessionAuthorizationExactOperationCredentialReadResult;
  exactReadCalled = false;

  constructor(readonly authorization: ExactEvmFamilyWalletSessionAuthorization) {
    this.read = {
      kind: 'found',
      record: authorization.session,
      operationCredential: authorization.operationCredential,
    };
  }

  async resolveSelectedWalletAuthority() {
    return {
      kind: 'resolved' as const,
      selection: {
        kind: 'wallet_selection_v1' as const,
        walletId: this.authorization.session.walletId,
        walletAuthMethodId: this.authorization.selectedAuthMethod.walletAuthMethodId,
        lockGeneration: 0,
        lockState: 'unlocked' as const,
        updatedAtMs: 2,
      },
      authMethod: this.authorization.selectedAuthMethod,
      authority: this.authorization.selectedAuthority,
      signerMaterials: [],
      exportRoot: null,
    };
  }

  async readExactWithOperationCredential() {
    this.exactReadCalled = true;
    return this.read;
  }

  async listWalletAuthMethodsForWallet() {
    if (this.authorization.runtime.authBinding.kind !== 'email_otp') {
      throw new Error('exact fixture must carry Email OTP runtime binding');
    }
    return [
      {
        ...this.authorization.selectedAuthMethod,
        localStatus: 'synced' as const,
        authority: this.authorization.runtime.authBinding.emailOtpAuthority,
      },
    ];
  }
}

test('Email OTP signing-session refresh resolves the selected exact primary credential', async () => {
  const capability = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
  const sealedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest: capability.manifest,
  });
  const runtimeResolution = resolveExactEcdsaSealedRuntime({
    manifest: capability.manifest,
    walletId: capability.manifest.signer.walletId,
    chainTarget: sealedRecord.ecdsaRestore.chainTarget,
    sealedRecords: [sealedRecord],
  });
  if (runtimeResolution.kind !== 'resolved') {
    throw new Error(`exact Email OTP runtime fixture did not resolve: ${runtimeResolution.reason}`);
  }
  const runtime = runtimeResolution.runtime;
  const authorization = await buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture({
    capability: capability.capability,
    runtime,
    label: 'signing-session-exact',
  });
  const harness = new ExactSessionReadHarness(authorization);
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalListWalletAuthMethodsForWallet = IndexedDBManager.listWalletAuthMethodsForWallet;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  IndexedDBManager.resolveSelectedWalletAuthority =
    harness.resolveSelectedWalletAuthority.bind(harness);
  IndexedDBManager.listWalletAuthMethodsForWallet =
    harness.listWalletAuthMethodsForWallet.bind(harness);
  walletSessionAuthorizations.readExactWithOperationCredential =
    harness.readExactWithOperationCredential.bind(harness);

  try {
    const resolved = await resolveExactEmailOtpEcdsaSigningSessionAuthority({
      walletId: capability.manifest.signer.walletId,
      chainTarget: sealedRecord.ecdsaRestore.chainTarget,
      manifest: capability.manifest,
      runtime,
    });
    expect(resolved).toMatchObject({
      kind: 'exact_evm_family_wallet_session_authorization_v1',
      selectedAuthority: authorization.selectedAuthority,
      selectedAuthMethod: authorization.selectedAuthMethod,
      session: authorization.session,
      operationCredential: authorization.operationCredential,
      runtime,
    });
    if (!resolved) throw new Error('exact Email OTP authorization fixture did not resolve');
    expect(emailOtpEcdsaSigningSessionAuthLane(resolved)).toEqual({
      kind: 'signing_session',
      curve: 'ecdsa',
      walletSessionToken: authorization.operationCredential.token,
      thresholdSessionId: runtime.sealedRecord.thresholdSessionId,
      chainTarget: runtime.chainTarget,
    });
    expect(harness.exactReadCalled).toBe(true);

    harness.read = { kind: 'missing' };
    await expect(
      resolveExactEmailOtpEcdsaSigningSessionAuthority({
        walletId: capability.manifest.signer.walletId,
        chainTarget: sealedRecord.ecdsaRestore.chainTarget,
        manifest: capability.manifest,
        runtime,
      }),
    ).resolves.toBeNull();
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    IndexedDBManager.listWalletAuthMethodsForWallet = originalListWalletAuthMethodsForWallet;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
  }
});
