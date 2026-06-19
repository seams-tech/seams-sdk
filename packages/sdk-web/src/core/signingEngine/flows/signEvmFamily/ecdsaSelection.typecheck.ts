import type {
  BudgetBlockedEvmFamilyEcdsaSigningSelection,
  EcdsaSelectionDiagnostics,
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { ReadyEcdsaMaterial } from './ecdsaMaterialState';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';

declare const readyMaterial: ReadyEcdsaMaterial;
declare const reauthAnchor: ReauthAnchorIdentity;
declare const diagnostics: EcdsaSelectionDiagnostics;

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
      signingGrantId: 'signing-grant-1',
    }),
    hasRecord: false,
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

const expiredSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
  material: missingHotMaterialSelection.material,
  reason: 'expired',
  reauthAnchor,
  diagnostics: readySelection.diagnostics,
};
void expiredSelection;

// @ts-expect-error exhausted/expired reauth selections require a ReauthAnchorIdentity.
const invalidExpiredSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
  material: missingHotMaterialSelection.material,
  reason: 'expired',
  diagnostics: readySelection.diagnostics,
};
void invalidExpiredSelection;

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

const diagnosticsAsReadySelectionMaterial: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  // @ts-expect-error diagnostics are observational and cannot satisfy ready material.
  material: diagnostics,
  diagnostics,
};
void diagnosticsAsReadySelectionMaterial;

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
