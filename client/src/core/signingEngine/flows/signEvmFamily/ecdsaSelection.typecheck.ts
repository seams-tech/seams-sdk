import type {
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { ReadyEcdsaMaterial } from './ecdsaMaterialState';

declare const readyMaterial: ReadyEcdsaMaterial;

const readySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: {} as ReadyEvmFamilyEcdsaSigningSelection['accountAuth'],
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: {} as ReadyEvmFamilyEcdsaSigningSelection['lane'],
  material: readyMaterial,
  diagnostics: {} as ReadyEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void readySelection;

const missingHotMaterialSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
  material: {
    kind: 'missing',
    authMethod: 'email_otp',
    source: 'email_otp',
    chainTarget: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['material']['chainTarget'],
    identity: {
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-signing-session-1',
    },
  },
  reason: 'missing_hot_material',
  diagnostics: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void missingHotMaterialSelection;

const invalidReadySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  // @ts-expect-error ready selections require ready_material
  material: missingHotMaterialSelection.material,
  diagnostics: readySelection.diagnostics,
};
void invalidReadySelection;

export {};
