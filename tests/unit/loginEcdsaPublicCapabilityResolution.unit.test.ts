import { expect, test } from '@playwright/test';
import {
  resolveActiveEcdsaCapabilityRuntime,
  type ActiveEcdsaCapabilityRuntimeReadPorts,
} from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

const missingCapabilityPorts: ActiveEcdsaCapabilityRuntimeReadPorts = {
  listActiveEcdsaCapabilityManifestsForWallet: async () => [],
  listExactSealedSessionsForWallet: async () => [],
  resolveSelectedWalletAuthority: async () => ({ kind: 'missing_selection' }),
};

// Login warm-up used to fall back to a composite-record scan when the
// configured target carried no persisted public capability, and threw when the
// scan found nothing -- which it always did. Public capability and authority
// are the manifest's half of the split; the sealed record is only correlated
// runtime evidence. With no canonical state the outcome is the existing typed
// device-link-required, never a record fallback.

test.describe('login ECDSA public capability resolution', () => {
  test('a persisted-capability miss resolves public capability from the manifest', () => {
    const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
    const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
    const walletId = toWalletId(String(manifest.signer.walletId));

    const resolution = resolveExactEcdsaSealedRuntime({
      manifest,
      walletId,
      chainTarget: record.ecdsaRestore.chainTarget,
      sealedRecords: [record],
    });
    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;

    // What login now reads on the persisted-capability miss path.
    const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
    expect(String(publicFacts.walletId)).toBe(String(walletId));
    expect(String(publicFacts.keyHandle)).toBe(resolution.runtime.keyHandle);

    // The sealed copy is correlated evidence, not the source: 6d.0 already
    // proved they agree, so login can take the manifest's copy directly.
    expect(record.ecdsaRestore.publicCapability).toEqual(publicFacts.publicCapability);
  });

  test('binding facts for the session come from the sealed runtime, not the manifest', () => {
    const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
    const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
    const walletId = toWalletId(String(manifest.signer.walletId));
    const resolution = resolveExactEcdsaSealedRuntime({
      manifest,
      walletId,
      chainTarget: record.ecdsaRestore.chainTarget,
      sealedRecords: [record],
    });
    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;

    const runtime = resolution.runtime;
    expect(runtime.authBinding.kind).toBe('email_otp');
    if (runtime.authBinding.kind !== 'email_otp') return;
    expect(runtime.authBinding.providerSubjectId).toBe(record.ecdsaRestore.providerSubjectId);
    expect(runtime.sealedRecord.authMethod).toBe('email_otp');
  });

  test('absent canonical capability blocks rather than falling back to a record scan', async () => {
    const resolution = await resolveActiveEcdsaCapabilityRuntime(
      missingCapabilityPorts,
      {
        walletId: toWalletId('no-manifest-wallet.testnet'),
        chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
      },
    );
    expect(resolution.kind).toBe('blocked');
    if (resolution.kind !== 'blocked') return;
    expect(resolution.reason).toBe('missing_capability');
  });
});
