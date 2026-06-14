import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { buildEvmFamilyPasskeyEcdsaProvisionPlan } from './provisionPlan';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { EvmFamilyEcdsaPasskeyStepUpAuthorization } from './stepUpAuthorization';

declare const authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
declare const lane: Pick<ResolvedEvmFamilyEcdsaSigningLane, 'key' | 'keyHandle' | 'chainTarget'>;
declare const record: ThresholdEcdsaSessionRecord;

void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  material: { kind: 'session_record', lane, record },
  sessionBudgetUses: 1,
});

void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  // @ts-expect-error passkey ECDSA provision must not accept sealed recovery material
  material: { kind: 'sealed_recovery', lane, record },
  sessionBudgetUses: 1,
});

void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  // @ts-expect-error passkey ECDSA provision requires an exact session record
  material: { kind: 'session_record', lane, record: null },
  sessionBudgetUses: 1,
});

// @ts-expect-error passkey ECDSA provision requires exact ready material
void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  sessionBudgetUses: 1,
});

void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  // @ts-expect-error passkey ECDSA provision requires exact ready material
  material: { kind: 'ready_evm_family_ecdsa_material' },
  sessionBudgetUses: 1,
});

export {};
