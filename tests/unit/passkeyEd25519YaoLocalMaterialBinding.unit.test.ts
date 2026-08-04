import { expect, test } from '@playwright/test';
import {
  metadataFromPasskeyEd25519YaoLocalMaterialBindingV1,
  parsePasskeyEd25519YaoLocalMaterialBindingV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildPasskeyEd25519YaoLocalMaterialBindingFixture } from './helpers/passkeyEd25519YaoLocalMaterial.fixtures';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';

test('accepts opaque activation refs independently from public material facts', () => {
  const parsed = parsePasskeyEd25519YaoLocalMaterialBindingV1(
    buildPasskeyEd25519YaoLocalMaterialBindingFixture(),
  );

  expect(parsed.materialActivation.keyBinding).not.toBe(parsed.registeredPublicKeyB64u);
  expect(parsed.materialActivation.lifecycleBinding).not.toBe(parsed.lifecycleId);
  expect(parsed.materialActivation.capability).not.toBe(parsed.activationCapabilityBindingB64u);
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

test('overlays a renewed threshold session onto imported metadata without changing the stored binding', () => {
  const parsed = parsePasskeyEd25519YaoLocalMaterialBindingV1(
    buildPasskeyEd25519YaoLocalMaterialBindingFixture(),
  );
  const renewed = parseThresholdEd25519SessionId('threshold-session-passkey-yao-renewed');
  if (!renewed.ok) throw new Error('invalid renewed threshold session fixture');

  const metadata = metadataFromPasskeyEd25519YaoLocalMaterialBindingV1(parsed, renewed.value);

  expect(metadata.scope.threshold_session_id).toBe(renewed.value);
  expect(parsed.thresholdSessionId).toBe('threshold-session-passkey-yao-local-material');
  expect(metadata.scope.material_activation).toEqual(
    expect.objectContaining({
      activation_id: parsed.materialActivation.activationId,
      capability: parsed.materialActivation.capability,
    }),
  );
});
