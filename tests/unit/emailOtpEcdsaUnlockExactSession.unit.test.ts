import { expect, test } from '@playwright/test';
import { IndexedDBManager } from '@/core/indexedDB';
import { resolveReusableEmailOtpEcdsaUnlockOperationCredential } from '@/core/signingEngine/session/emailOtp/ecdsaLogin';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ResolveSelectedWalletAuthorityResultV1 } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/repositories';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { EmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildEmailOtpEcdsaWalletSessionFixture,
  type EmailOtpEcdsaWalletSessionFixture,
} from './helpers/linkedDeviceManagement.fixtures';

function selectedAuthority(
  fixture: EmailOtpEcdsaWalletSessionFixture,
): ResolveSelectedWalletAuthorityResultV1 {
  return {
    kind: 'resolved',
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

function exactSessionRead(
  fixture: EmailOtpEcdsaWalletSessionFixture,
): WalletSessionAuthorizationExactOperationCredentialReadResult {
  return {
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  };
}

class ExactUnlockReadHarness {
  read: WalletSessionAuthorizationExactOperationCredentialReadResult;
  selected: ResolveSelectedWalletAuthorityResultV1;
  readonly exactReadInputs: Parameters<
    typeof walletSessionAuthorizations.readExactWithOperationCredential
  >[0][] = [];
  persistenceFailure = false;

  constructor(
    selected: ResolveSelectedWalletAuthorityResultV1,
    read: WalletSessionAuthorizationExactOperationCredentialReadResult,
    readonly exactFactorAuthority: EmailOtpWalletAuthAuthority,
  ) {
    this.read = read;
    this.selected = selected;
  }

  async resolveSelectedWalletAuthority() {
    return this.selected;
  }

  async listWalletAuthMethodsForWallet() {
    return [
      {
        ...this.selected.authMethod,
        localStatus: 'synced' as const,
        authority: this.exactFactorAuthority,
      },
    ];
  }

  async readExactWithOperationCredential(
    input: Parameters<typeof walletSessionAuthorizations.readExactWithOperationCredential>[0],
  ) {
    if (this.persistenceFailure) throw new Error('IndexedDB unavailable');
    this.exactReadInputs.push(input);
    return this.read;
  }
}

function installExactUnlockReadHarness(harness: ExactUnlockReadHarness): () => void {
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalListWalletAuthMethodsForWallet = IndexedDBManager.listWalletAuthMethodsForWallet;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  IndexedDBManager.resolveSelectedWalletAuthority =
    harness.resolveSelectedWalletAuthority.bind(harness);
  IndexedDBManager.listWalletAuthMethodsForWallet =
    harness.listWalletAuthMethodsForWallet.bind(harness);
  walletSessionAuthorizations.readExactWithOperationCredential =
    harness.readExactWithOperationCredential.bind(harness);
  return () => {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    IndexedDBManager.listWalletAuthMethodsForWallet = originalListWalletAuthMethodsForWallet;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
  };
}

test('reuses only the exact selected Email OTP ECDSA operation credential', async () => {
  const fixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'exact-reuse',
    expiresAtMs: Date.now() + 60_000,
  });
  const harness = new ExactUnlockReadHarness(
    selectedAuthority(fixture),
    exactSessionRead(fixture),
    fixture.exactFactorAuthority,
  );
  const restore = installExactUnlockReadHarness(harness);
  try {
    const credential = await resolveReusableEmailOtpEcdsaUnlockOperationCredential({
      walletId: fixture.authority.walletId,
      authority: fixture.factorAuthority,
      materialActivation: fixture.materialActivation,
    });

    expect(credential).toEqual(fixture.operationCredential);
    expect(harness.exactReadInputs).toEqual([
      {
        walletId: fixture.authority.walletId,
        authorityId: fixture.authority.authorityId,
        authMethodId: fixture.authMethod.walletAuthMethodId,
      },
    ]);
  } finally {
    restore();
  }
});

test('skips reuse when exact selection, authority, session, or ECDSA material is stale', async () => {
  const fixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'stale-reuse',
    expiresAtMs: Date.now() + 60_000,
  });
  const other = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'other-reuse',
    expiresAtMs: Date.now() + 60_000,
  });
  const lockedSelection: ResolveSelectedWalletAuthorityResultV1 = {
    ...selectedAuthority(fixture),
    selection: { ...fixture.selection, lockState: 'locked' },
  };
  const staleAuthorityDigest: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    ...exactSessionRead(fixture),
    record: {
      ...fixture.activeWalletSession,
      authorityDigestB64u: other.authority.authorityDigestB64u,
    },
  };
  const expired: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    ...exactSessionRead(fixture),
    record: { ...fixture.activeWalletSession, expiresAtMs: Date.now() - 1 },
  };
  const cases = [
    {
      selected: lockedSelection,
      read: exactSessionRead(fixture),
      materialActivation: fixture.materialActivation,
    },
    {
      selected: selectedAuthority(fixture),
      read: staleAuthorityDigest,
      materialActivation: fixture.materialActivation,
    },
    {
      selected: selectedAuthority(fixture),
      read: expired,
      materialActivation: fixture.materialActivation,
    },
    {
      selected: selectedAuthority(fixture),
      read: exactSessionRead(fixture),
      materialActivation: buildMpcMaterialActivationRefFixture('wrong-activation'),
    },
  ] as const;
  const harness = new ExactUnlockReadHarness(
    selectedAuthority(fixture),
    exactSessionRead(fixture),
    fixture.exactFactorAuthority,
  );
  const restore = installExactUnlockReadHarness(harness);
  try {
    for (const testCase of cases) {
      harness.selected = testCase.selected;
      harness.read = testCase.read;
      const credential = await resolveReusableEmailOtpEcdsaUnlockOperationCredential({
        walletId: fixture.authority.walletId,
        authority: fixture.factorAuthority,
        materialActivation: testCase.materialActivation,
      });
      expect(credential).toBeNull();
    }

    harness.selected = selectedAuthority(fixture);
    harness.read = exactSessionRead(fixture);
    const staleFactorCredential = await resolveReusableEmailOtpEcdsaUnlockOperationCredential({
      walletId: fixture.authority.walletId,
      authority: {
        ...fixture.factorAuthority,
        authorityDigest: other.factorAuthority.authorityDigest,
      },
      materialActivation: fixture.materialActivation,
    });
    expect(staleFactorCredential).toBeNull();
  } finally {
    restore();
  }
});

test('contains exact-session persistence failures as unavailable reuse', async () => {
  const fixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'persistence-failure',
    expiresAtMs: Date.now() + 60_000,
  });
  const harness = new ExactUnlockReadHarness(
    selectedAuthority(fixture),
    exactSessionRead(fixture),
    fixture.exactFactorAuthority,
  );
  harness.persistenceFailure = true;
  const restore = installExactUnlockReadHarness(harness);
  try {
    const credential = await resolveReusableEmailOtpEcdsaUnlockOperationCredential({
      walletId: fixture.authority.walletId,
      authority: fixture.factorAuthority,
      materialActivation: fixture.materialActivation,
    });

    expect(credential).toBeNull();
  } finally {
    restore();
  }
});
