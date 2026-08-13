import { expect, test } from '@playwright/test';
import { buildEcdsaServerActivationCommit } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import { parseEcdsaServerGeneration } from '@shared/utils/ecdsaCapabilityActivation';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';

test('accepts one exact server activation proof', () => {
  const fixture = ecdsaCapabilityActivationFixture();
  expect(
    buildEcdsaServerActivationCommit({
      activationBinding: fixture.prepareInput.activationBinding,
      serverCommit: fixture.serverCommit,
    }).kind,
  ).toBe('ecdsa_server_activation_commit');
});

test('rejects receipt identity that disagrees with the server commit', () => {
  const fixture = ecdsaCapabilityActivationFixture();
  const receipt = fixture.serverCommit.protocolReceipt;
  const mismatches = [
    {
      ...receipt,
      activation_correlation_id: parseCorrelationId('different-correlation'),
    },
    {
      ...receipt,
      activation_request_digest: { bytes: new Array<number>(32).fill(13) },
    },
    {
      ...receipt,
      server_generation: parseEcdsaServerGeneration('different-generation'),
    },
  ];

  for (const protocolReceipt of mismatches) {
    expect(() =>
      buildEcdsaServerActivationCommit({
        activationBinding: fixture.prepareInput.activationBinding,
        serverCommit: {
          ...fixture.serverCommit,
          protocolReceipt,
        },
      }),
    ).toThrow('ECDSA activation receipt does not match the server activation commit');
  }
});

test('rejects a substituted material activation receipt', () => {
  const fixture = ecdsaCapabilityActivationFixture();
  const receipt = fixture.serverCommit.protocolReceipt;
  const protocolReceipt = {
    ...receipt,
    ecdsa_activation: {
      ...receipt.ecdsa_activation,
      material_activation: {
        ...receipt.ecdsa_activation.material_activation,
        key_binding: 'substituted-material-key-binding',
      },
    },
  };

  expect(() =>
    buildEcdsaServerActivationCommit({
      activationBinding: fixture.prepareInput.activationBinding,
      serverCommit: {
        ...fixture.serverCommit,
        protocolReceipt,
      },
    }),
  ).toThrow('ECDSA activation receipt does not match the prepared material binding');
});
