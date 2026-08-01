import { expect, test } from '@playwright/test';
import { parsePasskeyEd25519YaoLocalMaterialBindingV1 } from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildPasskeyEd25519YaoLocalMaterialBindingFixture } from './helpers/passkeyEd25519YaoLocalMaterial.fixtures';

test('accepts opaque activation refs independently from public material facts', () => {
  const parsed = parsePasskeyEd25519YaoLocalMaterialBindingV1(
    buildPasskeyEd25519YaoLocalMaterialBindingFixture(),
  );

  expect(parsed.materialActivation.keyBinding).not.toBe(parsed.registeredPublicKeyB64u);
  expect(parsed.materialActivation.lifecycleBinding).not.toBe(parsed.lifecycleId);
  expect(parsed.materialActivation.capability).not.toBe(
    parsed.activationCapabilityBindingB64u,
  );
});

test('rejects an activation ref for another material owner or SigningWorker', () => {
  for (const materialActivation of [
    buildMpcMaterialActivationRefFixture(
      'passkey-yao-foreign-owner',
      'wallet-passkey-yao-foreign-owner',
      'signing-worker-passkey-yao-local-material',
    ),
    buildMpcMaterialActivationRefFixture(
      'passkey-yao-foreign-worker',
      'wallet-passkey-yao-local-material',
      'signing-worker-passkey-yao-foreign-worker',
    ),
  ]) {
    expect(() =>
      parsePasskeyEd25519YaoLocalMaterialBindingV1(
        buildPasskeyEd25519YaoLocalMaterialBindingFixture({ materialActivation }),
      ),
    ).toThrow('Stored Ed25519 Client material activation does not match its binding');
  }
});
