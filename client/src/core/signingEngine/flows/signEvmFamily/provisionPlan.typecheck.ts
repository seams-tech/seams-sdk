import type { ReadyEvmFamilyEcdsaMaterial } from '../../session/identity/evmFamilyEcdsaIdentity';
import { buildEvmFamilyPasskeyEcdsaProvisionPlan } from './provisionPlan';
import type { EvmFamilyEcdsaPasskeyStepUpAuthorization } from './stepUpAuthorization';

declare const authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
declare const material: ReadyEvmFamilyEcdsaMaterial;

void buildEvmFamilyPasskeyEcdsaProvisionPlan({
  authorization,
  material,
  sessionBudgetUses: 1,
});

// @ts-expect-error passkey ECDSA provision requires paired key-ref material
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
