import { expect, test } from '@playwright/test';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearSigningGrant,
  discoverLanesForWallet,
} from '@/core/signingEngine/session/availability/readiness';
import type { ClearVolatileWarmSessionMaterialCommand } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

const WALLET_ID = toWalletId('frost-clear-grant-k7p9m2');
const PRIMARY_GRANT_ID = 'grant-clear-split-ed25519-primary';
const SIBLING_GRANT_ID = 'grant-clear-split-ed25519-sibling';
const primaryRecord = buildPasskeyEd25519SealedSessionRecordFixture({
  walletId: WALLET_ID,
  nearAccountId: 'primary.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-clear-grant-primary',
  thresholdSessionId: 'tsess-clear-split-ed25519-primary',
  signingGrantId: PRIMARY_GRANT_ID,
});
const siblingRecord = buildPasskeyEd25519SealedSessionRecordFixture({
  walletId: WALLET_ID,
  nearAccountId: 'sibling.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-clear-grant-sibling',
  thresholdSessionId: 'tsess-clear-split-ed25519-sibling',
  signingGrantId: SIBLING_GRANT_ID,
});

test('clears the grant projection without treating durable seals as live worker bindings', async () => {
  const durableRecords = [primaryRecord, siblingRecord];
  const clearCommands: ClearVolatileWarmSessionMaterialCommand[] = [];
  const deps = {
    listExactSealedSessionsForWallet: async () => durableRecords,
    touchConfirm: {
      clearVolatileWarmSessionMaterial: async (
        command: ClearVolatileWarmSessionMaterialCommand,
      ) => {
        clearCommands.push(command);
      },
    },
  };

  await expect(discoverLanesForWallet(deps, WALLET_ID)).resolves.toHaveLength(2);
  await expect(
    clearSigningGrant({
      deps,
      statusOverrides: new Map(),
      walletId: WALLET_ID,
      signingGrantId: PRIMARY_GRANT_ID,
    }),
  ).resolves.toEqual({ kind: 'cleared' });

  expect(clearCommands).toEqual([]);
  expect(durableRecords).toEqual([primaryRecord, siblingRecord]);
});
