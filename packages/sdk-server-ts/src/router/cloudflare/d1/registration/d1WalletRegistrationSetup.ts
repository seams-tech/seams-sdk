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
 * The valuable consequence is that the ECDSA preparation — the Router call
 * that dominated the measured cold path — overlaps the user's authenticator
 * interaction instead of being serialized after it.
 *
 * Setup is ECDSA-only for both authentication methods. Yao admission binds the
 * Ed25519 authority scope, which is only sound once the proof is verified, so
 * respond derives it. Admitting at setup would have been possible for a
 * passkey and not for Email OTP, and two setup protocols split by auth method
 * is a worse contract than one that always defers.
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
  registrationSignerSetSelectionFromPlan,
  type RegisterWalletInput,
  type RegistrationAuthMethodInput,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  RespondEd25519DeferredWorkV2,
  WalletRegistrationRespondResponseV2,
  WalletRegistrationSetupResponseV2,
} from '../../../../core/threeRouteRegistrationContracts';
import type { StoredWalletRegistrationCeremony } from '../../../../core/RegistrationCeremonyStore';
import { thresholdEcdsaChainTargetFromValue } from '../../../../core/thresholdEcdsaChainTarget';
import {
  computeWalletRegistrationSetupDigestB64u,
  mintSignedWalletRegistrationSetup,
  type WalletRegistrationSetupMinter,
} from '../../../domains/walletRegistration/walletRegistrationSetupPayload';
import type {
  WalletRegistrationSetupRequest,
  WalletRegistrationSetupInput,
  WalletRegistrationRespondInput,
  WalletRegistrationActivateInput,
  WalletRegistrationNearProvisioningInput,
} from '../../../domains/walletRegistration/walletRegistrationInputs';

/** Setup's ceremony lives only as long as an authenticator prompt plausibly takes. */
const WALLET_REGISTRATION_SETUP_TTL_MS = 10 * 60_000;

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
    policy: input.ceremony.preparedContext.runtimePolicy,
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

/**
 * Builds respond's discriminated result. The signer plan decides the shape:
 * a mixed plan always carries its deferred NEAR work, an ECDSA-only plan has
 * no arm to omit. There is no optional `ed25519` member to forget to check.
 */
export function walletRegistrationRespondResult(input: {
  readonly ceremony: { readonly registrationCeremonyId: string };
  readonly strictResult: unknown;
  readonly ed25519: RespondEd25519DeferredWorkV2 | null;
}): WalletRegistrationRespondResponseV2 {
  const base = {
    ok: true as const,
    registrationCeremonyId: input.ceremony.registrationCeremonyId,
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_forwarded_v1' as const,
      strictResult: input.strictResult,
    },
  };
  return input.ed25519
    ? { ...base, kind: 'near_ed25519_and_evm_family_ecdsa', ed25519: input.ed25519 }
    : { ...base, kind: 'evm_family_ecdsa' };
}

/**
 * Recovers the deferred NEAR work from a ceremony that already advanced, so an
 * exact respond replay returns the same shape it returned the first time.
 */
export function storedRespondEd25519DeferredWork(
  signerState: StoredWalletRegistrationCeremony['signerState'],
): RespondEd25519DeferredWorkV2 | null {
  if (signerState.kind !== 'signer_set_registration') return null;
  const branch = signerState.branches.find(
    (candidate) => candidate.kind === 'near_ed25519_yao_authorized',
  );
  if (!branch || branch.kind !== 'near_ed25519_yao_authorized') return null;
  return {
    status: 'deferred',
    admissionRequest: branch.admissionRequest,
    admissionReceipt: branch.admissionReceipt,
  };
}

export function walletRegistrationSetupError(
  code: string,
  message: string,
): Extract<WalletRegistrationSetupResponseV2, { ok: false }> {
  return { ok: false, code, message };
}
