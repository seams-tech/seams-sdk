import type {
  BudgetBlockedEvmFamilyEcdsaSigningSelection,
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { ReadyEcdsaMaterial } from './ecdsaMaterialState';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';

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
    kind: 'public_identity_unavailable',
    authMethod: 'email_otp',
    source: 'email_otp',
    chainTarget: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['material']['chainTarget'],
    identity: buildEcdsaSessionIdentity({
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-signing-session-1',
    }),
    hasRecord: false,
    hasKeyRef: false,
  },
  reason: 'missing_hot_material',
  reauthAuthority: {
    kind: 'email_otp_signing_session',
    thresholdSessionId: 'threshold-session-1',
    chainTarget: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane']['chainTarget'],
  },
  diagnostics: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void missingHotMaterialSelection;

const invalidReadySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  // @ts-expect-error ready selections require ready-to-sign material
  material: missingHotMaterialSelection.material,
  diagnostics: readySelection.diagnostics,
};
void invalidReadySelection;

const invalidBudgetBlockedSelection: BudgetBlockedEvmFamilyEcdsaSigningSelection = {
  kind: 'budget_blocked',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: readySelection.lane,
  material: readyMaterial,
  // @ts-expect-error exhausted budgets must route through reauth_required
  budget: { kind: 'exhausted', remainingUses: 0 },
  diagnostics: readySelection.diagnostics,
};
void invalidBudgetBlockedSelection;

export {};
