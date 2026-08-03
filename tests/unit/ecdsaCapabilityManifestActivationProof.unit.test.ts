import { expect, test } from '@playwright/test';
import { buildServerCommittedEcdsaActivationJournal } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import { parseEcdsaServerGeneration } from '@shared/utils/ecdsaCapabilityActivation';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';

test('accepts one exact server activation proof', () => {
  const fixture = ecdsaCapabilityActivationFixture();
  expect(
    buildServerCommittedEcdsaActivationJournal({
      preparedJournal: fixture.preparedJournal,
      serverCommit: {
        correlationId: fixture.preparedJournal.journalId,
        activationRequestDigest: fixture.requestDigest,
        serverGeneration: fixture.serverGeneration,
        protocolReceipt: fixture.protocolReceipt,
      },
    }).kind,
  ).toBe('server_activation_committed');
});

test('rejects receipt identity that disagrees with the server commit', () => {
  const fixture = ecdsaCapabilityActivationFixture();
  const mismatches = [
    {
      ...fixture.protocolReceipt,
      activation_correlation_id: parseCorrelationId('different-correlation'),
    },
    {
      ...fixture.protocolReceipt,
      activation_request_digest: { bytes: new Array<number>(32).fill(13) },
    },
    {
      ...fixture.protocolReceipt,
      server_generation: parseEcdsaServerGeneration('different-generation'),
    },
  ];

  for (const protocolReceipt of mismatches) {
    expect(() =>
      buildServerCommittedEcdsaActivationJournal({
        preparedJournal: fixture.preparedJournal,
        serverCommit: {
          correlationId: fixture.preparedJournal.journalId,
          activationRequestDigest: fixture.requestDigest,
          serverGeneration: fixture.serverGeneration,
          protocolReceipt,
        },
      }),
    ).toThrow('ECDSA activation receipt does not match the server activation commit');
  }
});
