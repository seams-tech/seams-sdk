import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import type { NearAccountRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  getPrfResultsFromCredential,
  redactCredentialExtensionOutputs,
} from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  getLastLoggedInSignerSlot,
  parseSignerSlot,
} from '@/core/signingEngine/webauthnAuth/device/signerSlot';

export const PRF_MISSING_ERROR =
  'Missing PRF.first output from credential (requires a PRF-enabled passkey)';

export function generateNearSigningSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

export function toCredentialForRelayJson(
  credential?: WebAuthnAuthenticationCredential,
): string | undefined {
  return credential ? JSON.stringify(redactCredentialExtensionOutputs(credential)) : undefined;
}

export function requirePrfFirstFromCredential(
  credential?: WebAuthnAuthenticationCredential,
): string {
  const prfFirstB64u = getPrfResultsFromCredential(credential).first;
  if (!prfFirstB64u) {
    throw new Error(PRF_MISSING_ERROR);
  }
  return prfFirstB64u;
}

export type ResolvedNearSigningMaterials = {
  nearAccountId: AccountId;
  resolvedSignerSlot: number;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
  warnings: string[];
};

export async function resolveNearSigningMaterials(args: {
  ctx: SigningRuntimeDeps;
  nearAccount: NearAccountRef;
  signerSlot?: number;
  operationLabel: string;
  warnings?: string[];
}): Promise<ResolvedNearSigningMaterials> {
  const nearAccountId = toAccountId(args.nearAccount.accountId);
  const relayerUrl = args.ctx.relayerUrl;
  const warnings = args.warnings ?? [];

  const parsedSignerSlot = parseSignerSlot(args.signerSlot, { min: 1 });
  if (args.signerSlot !== undefined && parsedSignerSlot === null) {
    throw new Error(`Invalid signerSlot for ${args.operationLabel}: ${args.signerSlot}`);
  }
  const resolvedSignerSlot =
    parsedSignerSlot ??
    (await getLastLoggedInSignerSlot(nearAccountId, args.ctx.indexedDB.clientDB));

  const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
    {
      clientDB: args.ctx.indexedDB.clientDB,
      accountKeyMaterialDB: args.ctx.indexedDB.accountKeyMaterialDB,
    },
    nearAccountId,
    resolvedSignerSlot,
  );
  if (!thresholdKeyMaterial) {
    throw new Error('[SigningEngine] threshold key material is unavailable');
  }

  return {
    nearAccountId,
    resolvedSignerSlot,
    thresholdKeyMaterial,
    warnings,
  };
}
