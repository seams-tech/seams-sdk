import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { NearAccountRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519YaoMaterialExecutor } from '@/core/signingEngine/interfaces/near';
import { parseSignerSlot } from '@/core/signingEngine/webauthnAuth/device/signerSlot';

export type ResolvedNearSigningMaterials = {
  nearAccountId: AccountId;
  resolvedSignerSlot: number;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
  warnings: string[];
};

export async function resolveNearSigningMaterials(args: {
  materialExecutor: NearEd25519YaoMaterialExecutor;
  nearAccount: NearAccountRef;
  signerSlot: number;
  requestedSignerSlot?: number;
  operationLabel: string;
  warnings?: string[];
}): Promise<ResolvedNearSigningMaterials> {
  const nearAccountId = toAccountId(args.nearAccount.accountId);
  const warnings = args.warnings ?? [];

  const resolvedSignerSlot = parseSignerSlot(args.signerSlot, { min: 1 });
  if (resolvedSignerSlot === null) {
    throw new Error(`Invalid signerSlot for ${args.operationLabel}: ${args.signerSlot}`);
  }
  if (args.requestedSignerSlot !== undefined) {
    const requestedSignerSlot = parseSignerSlot(args.requestedSignerSlot, { min: 1 });
    if (requestedSignerSlot === null || requestedSignerSlot !== resolvedSignerSlot) {
      throw new Error(
        `Requested signerSlot does not match the selected signing lane for ${args.operationLabel}`,
      );
    }
  }

  const thresholdKeyMaterial = await args.materialExecutor.resolveSigningKeyMaterial();
  if (
    thresholdKeyMaterial.nearAccountId !== nearAccountId ||
    thresholdKeyMaterial.signerSlot !== resolvedSignerSlot
  ) {
    throw new Error('[SigningEngine] threshold key material does not match the selected lane');
  }
  return {
    nearAccountId,
    resolvedSignerSlot,
    thresholdKeyMaterial,
    warnings,
  };
}
