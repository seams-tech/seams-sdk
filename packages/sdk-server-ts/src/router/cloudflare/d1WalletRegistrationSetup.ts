/**
 * Refactor 94C. `/wallets/register/setup` — one request replacing the bootstrap
 * grant, the registration intent, and registration start.
 *
 * The three legs it replaces made six-plus serialized storage round trips
 * between them, most of it bookkeeping written on every request and read on
 * almost none: a grant record so the next leg could read back a decision the
 * grant check had already made, a wallet reservation so a later insert would
 * not collide, and a start journal so a duplicate start could be reconciled.
 * Collapsing the legs removes the readers, so the writes go too.
 *
 * What remains is one canonical D1 write: the ceremony row. That row is the
 * ceremony's existence — it is not insurance against a failure elsewhere.
 *
 * Setup necessarily runs *before* the client's WebAuthn create, because setup
 * issues the challenge that create must sign. So it stores the ceremony with
 * its authority awaiting proof, and respond binds the proof one leg later.
 * The valuable consequence is that the expensive Router preparation overlaps
 * the user's authenticator interaction instead of being serialized after it.
 *
 * The wallet reservation is deliberately not carried over. It existed so a
 * randomly generated wallet id allocated at intent time could not be taken
 * before start inserted the ceremony — a window that no longer exists now that
 * allocation and insertion are the same request. Genuine uniqueness is still
 * arbitrated where it always was, by the wallet table at commit.
 */

import {
  computeRegistrationIntentDigestB64u,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerPlan,
  registrationEd25519AuthorityScopeFromAuthMethod,
  registrationSignerSetSelectionFromPlan,
  type RegisterWalletInput,
  type RegistrationAuthMethodInput,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { ThresholdRuntimePolicyScope } from '../../core/types';
import type {
  SetupEd25519PreparationV2,
  WalletRegistrationSetupResponseV2,
} from '../../core/threeRouteRegistrationContracts';
import type { StoredWalletRegistrationCeremony } from '../../core/RegistrationCeremonyStore';
import { thresholdEcdsaChainTargetFromValue } from '../../core/thresholdEcdsaChainTarget';
import {
  computeWalletRegistrationSetupDigestB64u,
  mintSignedWalletRegistrationSetup,
  type WalletRegistrationSetupMinter,
} from '../walletRegistrationSetupPayload';

/** Setup's ceremony lives only as long as an authenticator prompt plausibly takes. */
const WALLET_REGISTRATION_SETUP_TTL_MS = 10 * 60_000;

export type WalletRegistrationSetupRequest = {
  readonly wallet?: RegisterWalletInput;
  readonly signerSelection: RegistrationSignerSetSelection;
  readonly authMethod: RegistrationAuthMethodInput;
};

export type WalletRegistrationSetupInput = {
  readonly request: WalletRegistrationSetupRequest;
  readonly orgId: string;
  readonly expectedOrigin: string;
  /* The Gateway session signer, supplied at the route boundary where the
     other wallet-session minting already happens. Gateway is the sole
     minting authority (94C checkpoint decision 4). */
  readonly signer: WalletRegistrationSetupMinter;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
};

export function walletRegistrationSetupIds(): {
  readonly registrationCeremonyId: string;
  readonly registrationPreparationId: string;
} {
  /* Both ids are freshly random. Start derived them from the intent grant so a
     duplicate start could reconcile to the same ceremony; setup has no earlier
     leg to reconcile with, so there is nothing to derive them from. */
  return {
    registrationCeremonyId: `wrc_${secureRandomBase64Url(32)}`,
    registrationPreparationId: `regprep_${secureRandomBase64Url(32)}`,
  };
}

/**
 * Resolves the wallet id without reserving it.
 *
 * A provided id is taken as given; an absent or server-allocated one is
 * generated. There is no existence pre-check: it cost a serialized read on
 * every registration to catch a collision that the commit-time uniqueness
 * constraint catches anyway, and for a freshly generated random id it could
 * essentially never fire.
 */
export function resolveWalletRegistrationSetupWalletId(input: {
  readonly wallet: RegisterWalletInput | undefined;
  readonly parseProvided: (raw: unknown) => WalletId | null;
  readonly createServerAllocated: () => WalletId;
}):
  | { readonly ok: true; readonly walletId: WalletId }
  | { readonly ok: false; readonly code: string; readonly message: string } {
  const wallet = input.wallet;
  if (!wallet || wallet.kind === 'server_allocated') {
    return { ok: true, walletId: input.createServerAllocated() };
  }
  if (wallet.kind === 'provided') {
    const walletId = input.parseProvided(wallet.walletId);
    if (!walletId) {
      return { ok: false, code: 'invalid_body', message: 'walletId is required' };
    }
    return { ok: true, walletId };
  }
  return { ok: false, code: 'invalid_body', message: 'wallet.kind is unsupported' };
}

export function walletRegistrationSetupEd25519Deferral(
  authMethod: RegistrationAuthMethodInput,
): SetupEd25519PreparationV2 | null {
  return registrationEd25519AuthorityScopeFromAuthMethod(authMethod)
    ? null
    : { status: 'deferred_to_respond', reason: 'authority_scope_requires_proof' };
}

export function normalizeWalletRegistrationSetupRequest(request: WalletRegistrationSetupRequest):
  | {
      readonly ok: true;
      readonly signerSelection: RegistrationSignerSetSelection;
      readonly authMethod: RegistrationAuthMethodInput;
    }
  | { readonly ok: false; readonly code: string; readonly message: string } {
  const signerPlan = normalizeRegistrationSignerPlan(request?.signerSelection);
  if (!signerPlan.ok) return signerPlan;
  const signerSelection = registrationSignerSetSelectionFromPlan(signerPlan.value, {
    normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
  });
  if (!signerSelection.ok) return signerSelection;
  const authMethod = normalizeRegistrationAuthMethodInput(request?.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
  }
  return { ok: true, signerSelection: signerSelection.value, authMethod };
}

export function walletRegistrationSetupExpiresAtMs(nowMs: number): number {
  return nowMs + WALLET_REGISTRATION_SETUP_TTL_MS;
}

/**
 * Mints the payload routes 2 and 3 verify, over setup's own canonical digest.
 */
export async function buildWalletRegistrationSetupSignature(input: {
  readonly signer: WalletRegistrationSetupMinter;
  readonly ceremony: StoredWalletRegistrationCeremony;
  readonly expectedOrigin: string;
}): Promise<{
  readonly signedSetup: Awaited<ReturnType<typeof mintSignedWalletRegistrationSetup>>;
  readonly setupDigestB64u: string;
}> {
  const signingRootId = toOptionalTrimmedString(input.ceremony.signingRootId) || '';
  const signingRootVersion = toOptionalTrimmedString(input.ceremony.signingRootVersion) || '';
  const setupDigestB64u = await computeWalletRegistrationSetupDigestB64u({
    registrationCeremonyId: input.ceremony.registrationCeremonyId,
    intent: input.ceremony.intent,
    intentDigestB64u: input.ceremony.digestB64u,
    orgId: input.ceremony.orgId,
    signingRootId,
    signingRootVersion,
    expectedOrigin: input.expectedOrigin,
  });
  const signedSetup = await mintSignedWalletRegistrationSetup(input.signer, {
    kind: 'wallet_registration_setup_v1',
    registrationCeremonyId: input.ceremony.registrationCeremonyId,
    walletId: String(input.ceremony.intent.walletId),
    orgId: input.ceremony.orgId,
    signingRootId,
    signingRootVersion,
    setupDigestB64u,
    expiresAtMs: input.ceremony.expiresAtMs,
  });
  return { signedSetup, setupDigestB64u };
}

export async function walletRegistrationSetupIntentDigest(
  intent: StoredWalletRegistrationCeremony['intent'],
): Promise<string> {
  return await computeRegistrationIntentDigestB64u(intent);
}

export function walletRegistrationSetupError(
  code: string,
  message: string,
): Extract<WalletRegistrationSetupResponseV2, { ok: false }> {
  return { ok: false, code, message };
}
