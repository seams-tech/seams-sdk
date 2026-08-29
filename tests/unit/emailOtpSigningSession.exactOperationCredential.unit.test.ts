import { expect, test } from '@playwright/test';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  walletSessionAuthorizations,
  type WalletSessionAuthorizationExactOperationCredentialReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { resolveExactEmailOtpEcdsaSigningSessionAuthority } from '@/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  buildEmailOtpEcdsaWalletSessionFixture,
  type EmailOtpEcdsaWalletSessionFixture,
} from './helpers/linkedDeviceManagement.fixtures';

function selectedAuthority(fixture: EmailOtpEcdsaWalletSessionFixture) {
  return {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

class ExactSessionReadHarness {
  read: WalletSessionAuthorizationExactOperationCredentialReadResult;
  activeReadCalled = false;

  constructor(readonly fixture: EmailOtpEcdsaWalletSessionFixture) {
    this.read = {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
  }

  async resolveSelectedWalletAuthority() {
    return selectedAuthority(this.fixture);
  }

  async readExactWithOperationCredential() {
    return this.read;
  }

  async listWalletAuthMethodsForWallet() {
    return [
      {
        ...this.fixture.authMethod,
        localStatus: 'synced' as const,
        authority: this.fixture.exactFactorAuthority,
      },
    ];
  }

  async rejectActiveWalletRead(): Promise<never> {
    this.activeReadCalled = true;
    throw new Error('wallet-wide session lookup must not run');
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
  const fixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'signing-session-exact',
    expiresAtMs: Date.now() + 60_000,
    walletId: String(capability.manifest.signer.walletId),
    walletAuthMethodId: String(capability.manifest.signer.authority.walletAuthMethodId),
    materialActivation: runtime.materialActivation,
    providerUserId: `google:${String(capability.manifest.signer.walletId)}`,
    emailHashHex: 'email-hash',
  });
  const harness = new ExactSessionReadHarness(fixture);
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalListWalletAuthMethodsForWallet = IndexedDBManager.listWalletAuthMethodsForWallet;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  const originalReadActive = walletSessionAuthorizations.readActiveForWallet;
  IndexedDBManager.resolveSelectedWalletAuthority =
    harness.resolveSelectedWalletAuthority.bind(harness);
  IndexedDBManager.listWalletAuthMethodsForWallet =
    harness.listWalletAuthMethodsForWallet.bind(harness);
  walletSessionAuthorizations.readExactWithOperationCredential =
    harness.readExactWithOperationCredential.bind(harness);
  walletSessionAuthorizations.readActiveForWallet = harness.rejectActiveWalletRead.bind(harness);

  try {
    const authority = await resolveExactEmailOtpEcdsaSigningSessionAuthority({
      walletId: capability.manifest.signer.walletId,
      chainTarget: sealedRecord.ecdsaRestore.chainTarget,
      manifest: capability.manifest,
      runtime,
    });
    expect(authority).toMatchObject({
      authority: runtime.authBinding.emailOtpAuthority,
      authLane: {
        kind: 'signing_session',
        curve: 'ecdsa',
        walletSessionToken: fixture.operationCredential.token,
        thresholdSessionId: runtime.sealedRecord.thresholdSessionId,
        chainTarget: runtime.chainTarget,
      },
    });
    expect(harness.activeReadCalled).toBe(false);

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
    walletSessionAuthorizations.readActiveForWallet = originalReadActive;
  }
});
