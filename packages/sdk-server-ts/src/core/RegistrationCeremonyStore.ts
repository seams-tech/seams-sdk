import type {
  CloudflareDurableObjectNamespaceLike,
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssPersistedPreparedServerSession,
  ThresholdEd25519HssPersistedRespondedServerSession,
  ThresholdEd25519HssPersistedServerInputs,
  ThresholdEd25519HssRegistrationPreparedServerState,
  ThresholdEd25519HssRegistrationRespondedServerState
} from './types';
import type {
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationPreparationId,
  WalletAddSignerStartResponse,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationStartResponse,
  WalletId
} from './registrationContracts';
import type {
  ServerAllocatedWalletId,
  RegistrationAuthority,
  RegistrationEd25519AuthorityScope,
  RegistrationSignerBranchKey,
} from '@shared/utils/registrationIntent';
import {
  addAuthMethodIntentGrantFromString,
  createServerAllocatedWalletId,
  normalizeAddAuthMethodInput,
  requireServerAllocatedWalletId,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseOrgId,
  parseProviderSubject,
  parseWalletId,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { NormalizedLogger } from './logger';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from './defaultConfigsServer';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
} from './ThresholdService/validation';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

export type StoredRegistrationIntent = {
  kind: 'intent_allocated';
  grant: RegistrationIntentGrant;
  intent: RegistrationIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
  failedAtMs?: never;
  failure?: never;
};

export type ConsumedRegistrationIntent = Omit<StoredRegistrationIntent, 'kind' | 'consumedAtMs'> & {
  kind: 'intent_consumed';
  consumedAtMs: number;
};

export type FailedRegistrationIntent = Omit<
  StoredRegistrationIntent,
  'kind' | 'failedAtMs' | 'failure'
> & {
  kind: 'intent_failed';
  failedAtMs: number;
  failure: {
    code: string;
    message: string;
  };
};

export type StoredAddSignerIntent = {
  kind: 'add_signer_intent_allocated';
  grant: AddSignerIntentGrant;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
};

export type ConsumedAddSignerIntent = Omit<StoredAddSignerIntent, 'kind' | 'consumedAtMs'> & {
  kind: 'add_signer_intent_consumed';
  consumedAtMs: number;
};

export type StoredAddAuthMethodIntent = {
  kind: 'add_auth_method_intent_allocated';
  grant: AddAuthMethodIntentGrant;
  intent: AddAuthMethodIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
};

export type ConsumedAddAuthMethodIntent = Omit<
  StoredAddAuthMethodIntent,
  'kind' | 'consumedAtMs'
> & {
  kind: 'add_auth_method_intent_consumed';
  consumedAtMs: number;
};

export type StoredRegistrationWebAuthnCredential = {
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
};

export type StoredRegistrationAuthority = RegistrationAuthority;

type WalletRegistrationEd25519StartPayload = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ed25519']
>;

type WalletRegistrationEcdsaStartPayload = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ecdsa']
>;

type WalletAddSignerEd25519StartPayload = NonNullable<
  Extract<WalletAddSignerStartResponse, { ok: true }>['ed25519']
>;

type WalletAddSignerEcdsaStartPayload = NonNullable<
  Extract<WalletAddSignerStartResponse, { ok: true }>['ecdsa']
>;

export type StoredEd25519RegistrationPrepared = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_prepared';
  serverState: ThresholdEd25519HssRegistrationPreparedServerState;
  responded?: never;
};

export type StoredEd25519RegistrationPrepareScope = {
  walletId: string;
  registrationIntentDigestB64u: string;
  authorityScope: RegistrationEd25519AuthorityScope;
  expectedOrigin: string;
  orgId: string;
  signingRootId: string;
  signingRootVersion: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
  participantIds: number[];
};

export type StoredWalletRegistrationHssPreparationBase = {
  registrationPreparationId: RegistrationPreparationId;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  authority: StoredRegistrationAuthority;
  orgId: string;
  expectedOrigin: string;
  signingRootId: string;
  signingRootVersion: string;
  ed25519Scope: StoredEd25519RegistrationPrepareScope;
  createdAtMs: number;
  expiresAtMs: number;
};

export type StoredWalletRegistrationHssPreparationPreparing =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_preparing';
    prepared?: never;
    failure?: never;
    consumedAtMs?: never;
  };

export type StoredWalletRegistrationHssPreparationPrepared =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_prepared';
    prepared: StoredEd25519RegistrationPrepared;
    failure?: never;
    consumedAtMs?: never;
  };

export type StoredWalletRegistrationHssPreparationFailed =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_failed';
    failure: {
      code: string;
      message: string;
    };
    prepared?: never;
    consumedAtMs?: never;
  };

export type StoredWalletRegistrationHssPreparation =
  | StoredWalletRegistrationHssPreparationPreparing
  | StoredWalletRegistrationHssPreparationPrepared
  | StoredWalletRegistrationHssPreparationFailed;

export type StoredWalletRegistrationPreparation = StoredWalletRegistrationHssPreparation;

export function buildStoredWalletRegistrationHssPreparationPreparing(
  input: StoredWalletRegistrationHssPreparationBase,
): StoredWalletRegistrationHssPreparationPreparing {
  return {
    kind: 'hss_prepare_preparing',
    ...input,
  };
}

export function buildStoredWalletRegistrationHssPreparationPrepared(
  input: StoredWalletRegistrationHssPreparationBase & {
    prepared: StoredEd25519RegistrationPrepared;
  },
): StoredWalletRegistrationHssPreparationPrepared {
  return {
    kind: 'hss_prepare_prepared',
    ...input,
  };
}

export function buildStoredWalletRegistrationHssPreparationFailed(
  input: StoredWalletRegistrationHssPreparationBase & {
    failure: {
      code: string;
      message: string;
    };
  },
): StoredWalletRegistrationHssPreparationFailed {
  return {
    kind: 'hss_prepare_failed',
    ...input,
  };
}

export function storedThresholdEd25519HssRespondedServerState(
  input: ThresholdEd25519HssRegistrationRespondedServerState,
): ThresholdEd25519HssRegistrationRespondedServerState {
  return input;
}

function assertNever(value: never): never {
  throw new Error(`Unexpected registration ceremony store branch: ${String(value)}`);
}

export function getPreparedWalletRegistrationHssPreparation(
  preparation: StoredWalletRegistrationHssPreparation,
):
  | { ok: true; preparation: StoredWalletRegistrationHssPreparationPrepared }
  | {
      ok: false;
      code: 'registration_preparation_pending' | 'registration_preparation_failed';
      message: string;
    } {
  switch (preparation.kind) {
    case 'hss_prepare_prepared':
      return { ok: true, preparation };
    case 'hss_prepare_preparing':
      return {
        ok: false,
        code: 'registration_preparation_pending',
        message: 'registration preparation is still running',
      };
    case 'hss_prepare_failed':
      return {
        ok: false,
        code: 'registration_preparation_failed',
        message: preparation.failure.message || 'registration preparation failed',
      };
    default:
      return assertNever(preparation);
  }
}

export function storedEd25519RegistrationPrepareScopesMatch(
  left: StoredEd25519RegistrationPrepareScope,
  right: StoredEd25519RegistrationPrepareScope,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.registrationIntentDigestB64u === right.registrationIntentDigestB64u &&
    registrationEd25519AuthorityScopesMatch(left.authorityScope, right.authorityScope) &&
    left.expectedOrigin === right.expectedOrigin &&
    left.orgId === right.orgId &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.signerSlot === right.signerSlot &&
    left.keyPurpose === right.keyPurpose &&
    left.keyVersion === right.keyVersion &&
    left.derivationVersion === right.derivationVersion &&
    left.participantIds.length === right.participantIds.length &&
    left.participantIds.every((id, index) => id === right.participantIds[index])
  );
}

function registrationEd25519AuthorityScopesMatch(
  left: RegistrationEd25519AuthorityScope,
  right: RegistrationEd25519AuthorityScope,
): boolean {
  switch (left.kind) {
    case 'passkey':
      return right.kind === 'passkey' && left.rpId === right.rpId;
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.provider === right.provider &&
        left.providerUserId === right.providerUserId
      );
    default: {
      const exhaustive: never = left;
      return exhaustive;
    }
  }
}

export function storedRegistrationAuthoritiesMatch(
  left: StoredRegistrationAuthority,
  right: StoredRegistrationAuthority,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.walletId === right.walletId &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u &&
        left.credentialPublicKeyB64u === right.credentialPublicKeyB64u &&
        left.registrationIntentDigestB64u === right.registrationIntentDigestB64u
      );
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.proofKind === right.proofKind &&
        left.walletId === right.walletId &&
        left.providerSubject === right.providerSubject &&
        left.emailHashHex === right.emailHashHex &&
        left.registrationAuthorityId === right.registrationAuthorityId &&
        left.finalWalletId === right.finalWalletId &&
        left.orgId === right.orgId &&
        left.registrationIntentDigestB64u === right.registrationIntentDigestB64u
      );
    default: {
      const exhaustive: never = left;
      return exhaustive;
    }
  }
}

export type ConsumeRegistrationIntentForPreparationInput = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  registrationPreparationId: RegistrationPreparationId;
  authority: StoredRegistrationAuthority;
  ed25519Scope: StoredEd25519RegistrationPrepareScope;
};

export type ConsumeRegistrationIntentForPreparationResult =
  | {
      ok: true;
      intent: ConsumedRegistrationIntent;
    }
  | {
      ok: false;
      code: 'invalid_grant' | 'scope_mismatch';
      message: string;
    };

function registrationPreparationMatchesIntentConsume(
  preparation: StoredWalletRegistrationHssPreparation,
  input: ConsumeRegistrationIntentForPreparationInput,
): boolean {
  return (
    preparation.kind === 'hss_prepare_prepared' &&
    preparation.registrationIntentGrant === input.registrationIntentGrant &&
    preparation.registrationIntentDigestB64u === input.registrationIntentDigestB64u &&
    storedRegistrationAuthoritiesMatch(preparation.authority, input.authority) &&
    storedEd25519RegistrationPrepareScopesMatch(preparation.ed25519Scope, input.ed25519Scope)
  );
}
export type StoredEd25519RegistrationResponded = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_responded';
  serverState: ThresholdEd25519HssRegistrationRespondedServerState;
  responded: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
};

export type StoredEd25519RegistrationFinalizing = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_finalizing';
  serverState: ThresholdEd25519HssRegistrationRespondedServerState;
  responded: StoredEd25519RegistrationResponded['responded'];
  finalizingAtMs: number;
};

export type StoredEd25519RegistrationCompleted = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_completed';
  serverState: ThresholdEd25519HssRegistrationRespondedServerState;
  responded: StoredEd25519RegistrationResponded['responded'];
  completedAtMs: number;
  walletId: WalletId;
};

type StoredEcdsaRegistrationBase = Omit<WalletRegistrationEcdsaStartPayload, 'kind'> & {
  hssKind: WalletRegistrationEcdsaStartPayload['kind'];
};

export type StoredEcdsaRegistrationPrepared = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_prepared';
  responded?: never;
  completed?: never;
};

export type StoredEcdsaRegistrationResponded = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_responded';
  responded: {
    bootstrap: EcdsaHssServerBootstrapResponse;
  };
  completed?: never;
};

export type StoredEcdsaRegistrationCompleted = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_completed';
  responded: StoredEcdsaRegistrationResponded['responded'];
  completedAtMs: number;
  walletId: WalletId;
  walletKeys: WalletRegistrationEcdsaWalletKey[];
};

export type StoredWalletRegistrationNearEd25519PreparedBranch = Omit<
  StoredEd25519RegistrationPrepared,
  'kind'
> & {
  kind: 'near_ed25519_prepared';
  branchKey: RegistrationSignerBranchKey;
};

export type StoredWalletRegistrationNearEd25519RespondedBranch = Omit<
  StoredEd25519RegistrationResponded,
  'kind'
> & {
  kind: 'near_ed25519_responded';
  branchKey: RegistrationSignerBranchKey;
};

export type StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch = Omit<
  StoredEcdsaRegistrationPrepared,
  'kind'
> & {
  kind: 'evm_family_ecdsa_prepared';
  branchKey: RegistrationSignerBranchKey;
};

export type StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch = Omit<
  StoredEcdsaRegistrationResponded,
  'kind'
> & {
  kind: 'evm_family_ecdsa_responded';
  branchKey: RegistrationSignerBranchKey;
};

export type StoredWalletRegistrationSignerBranch =
  | StoredWalletRegistrationNearEd25519PreparedBranch
  | StoredWalletRegistrationNearEd25519RespondedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch;

export type StoredWalletRegistrationSignerSetState = {
  kind: 'signer_set_registration';
  branches: readonly StoredWalletRegistrationSignerBranch[];
};

export type StoredWalletRegistrationNearEd25519Branch =
  | StoredWalletRegistrationNearEd25519PreparedBranch
  | StoredWalletRegistrationNearEd25519RespondedBranch;

export type StoredWalletRegistrationEvmFamilyEcdsaBranch =
  | StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch;

export function buildStoredWalletRegistrationNearEd25519PreparedBranch(input: {
  readonly branchKey: RegistrationSignerBranchKey;
  readonly prepared: {
    readonly ceremonyHandle: string;
    readonly preparedSession: StoredWalletRegistrationNearEd25519PreparedBranch['preparedSession'];
    readonly clientOtOfferMessageB64u: string;
    readonly serverState: ThresholdEd25519HssRegistrationPreparedServerState;
  };
}): StoredWalletRegistrationNearEd25519PreparedBranch {
  return {
    kind: 'near_ed25519_prepared',
    branchKey: input.branchKey,
    ceremonyHandle: input.prepared.ceremonyHandle,
    preparedSession: input.prepared.preparedSession,
    clientOtOfferMessageB64u: input.prepared.clientOtOfferMessageB64u,
    serverState: input.prepared.serverState,
  };
}

export function buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch(input: {
  readonly branchKey: RegistrationSignerBranchKey;
  readonly ecdsa: {
    readonly kind: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['hssKind'];
    readonly chainTargets: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['chainTargets'];
    readonly prepare: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['prepare'];
  };
}): StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch {
  return {
    kind: 'evm_family_ecdsa_prepared',
    branchKey: input.branchKey,
    hssKind: input.ecdsa.kind,
    chainTargets: input.ecdsa.chainTargets,
    prepare: input.ecdsa.prepare,
  };
}

export function findStoredWalletRegistrationNearEd25519Branch(
  state: StoredWalletRegistrationSignerSetState,
): StoredWalletRegistrationNearEd25519Branch | null {
  for (const branch of state.branches) {
    if (branch.kind === 'near_ed25519_prepared' || branch.kind === 'near_ed25519_responded') {
      return branch;
    }
  }
  return null;
}

export function findStoredWalletRegistrationEvmFamilyEcdsaBranch(
  state: StoredWalletRegistrationSignerSetState,
): StoredWalletRegistrationEvmFamilyEcdsaBranch | null {
  for (const branch of state.branches) {
    if (
      branch.kind === 'evm_family_ecdsa_prepared' ||
      branch.kind === 'evm_family_ecdsa_responded'
    ) {
      return branch;
    }
  }
  return null;
}

export function replaceStoredWalletRegistrationSignerBranch(input: {
  readonly state: StoredWalletRegistrationSignerSetState;
  readonly replacement: StoredWalletRegistrationSignerBranch;
}): StoredWalletRegistrationSignerSetState {
  return {
    kind: 'signer_set_registration',
    branches: input.state.branches.map((branch) =>
      branch.branchKey === input.replacement.branchKey ? input.replacement : branch,
    ),
  };
}

export type StoredWalletRegistrationFailed = {
  kind: 'registration_failed';
  failedAtMs: number;
  failure: {
    code: string;
    message: string;
  };
  ceremonyHandle?: never;
  preparedSession?: never;
  clientOtOfferMessageB64u?: never;
  prepare?: never;
  walletKeys?: never;
  responded?: never;
  completed?: never;
};

export type StoredWalletRegistrationSignerState =
  | StoredEd25519RegistrationPrepared
  | StoredEd25519RegistrationResponded
  | StoredEd25519RegistrationFinalizing
  | StoredEd25519RegistrationCompleted
  | StoredEcdsaRegistrationPrepared
  | StoredEcdsaRegistrationResponded
  | StoredEcdsaRegistrationCompleted
  | StoredWalletRegistrationSignerSetState
  | StoredWalletRegistrationFailed;

type StoredWalletRegistrationCeremonyBase = {
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  authority: StoredRegistrationAuthority;
};

export type StoredWalletRegistrationCeremony = StoredWalletRegistrationCeremonyBase & {
  signerState: StoredWalletRegistrationSignerState;
};

export type StoredWalletRegistrationFinalizeReplay = {
  kind: 'wallet_registration_finalize_replay_v1';
  registrationCeremonyId: string;
  idempotencyKey: string;
  response: Extract<WalletRegistrationFinalizeResponse, { ok: true }>;
  createdAtMs: number;
  expiresAtMs: number;
};

export type StoredEd25519AddSignerPrepared = WalletAddSignerEd25519StartPayload & {
  kind: 'ed25519_add_signer_prepared';
  serverState: ThresholdEd25519HssRegistrationPreparedServerState;
  responded?: never;
};

export type StoredEd25519AddSignerResponded = WalletAddSignerEd25519StartPayload & {
  kind: 'ed25519_add_signer_responded';
  serverState: ThresholdEd25519HssRegistrationRespondedServerState;
  responded: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
};

type StoredEcdsaAddSignerBase = Omit<WalletAddSignerEcdsaStartPayload, 'kind'> & {
  hssKind: WalletAddSignerEcdsaStartPayload['kind'];
};

export type StoredEcdsaAddSignerPrepared = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_prepared';
  responded?: never;
  completed?: never;
};

export type StoredEcdsaAddSignerResponded = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_responded';
  responded: {
    bootstrap: EcdsaHssServerBootstrapResponse;
  };
  completed?: never;
};

export type StoredEcdsaAddSignerCompleted = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_completed';
  responded: StoredEcdsaAddSignerResponded['responded'];
  completedAtMs: number;
  walletId: WalletId;
  walletKeys: WalletRegistrationEcdsaWalletKey[];
};

export type StoredWalletAddSignerSignerState =
  | StoredEd25519AddSignerPrepared
  | StoredEd25519AddSignerResponded
  | StoredEcdsaAddSignerPrepared
  | StoredEcdsaAddSignerResponded
  | StoredEcdsaAddSignerCompleted;

export type StoredWalletAddSignerCeremony = {
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expiresAtMs: number;
  auth:
    | {
        kind: 'webauthn_assertion';
        rpId: string;
        credentialIdB64u: string;
      }
    | {
        kind: 'app_session';
      };
  signerState: StoredWalletAddSignerSignerState;
};

export type StoredWalletAddAuthMethodCeremony = {
  addAuthMethodCeremonyId: string;
  intent: AddAuthMethodIntentV1;
  digestB64u: string;
  orgId: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  auth:
    | {
        kind: 'webauthn_assertion';
        rpId: string;
        credentialIdB64u: string;
      }
    | {
        kind: 'app_session';
      };
  authority: StoredRegistrationAuthority;
};

export interface RegistrationCeremonyStore {
  reserveServerAllocatedWalletId(input: {
    walletId: ServerAllocatedWalletId;
    expiresAtMs: number;
  }): Promise<boolean>;
  putIntent(intent: StoredRegistrationIntent): Promise<void>;
  getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null>;
  takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null>;
  consumeRegistrationIntentForPreparation(
    input: ConsumeRegistrationIntentForPreparationInput,
  ): Promise<ConsumeRegistrationIntentForPreparationResult>;
  putPreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void>;
  getPreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null>;
  updatePreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void>;
  takePreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null>;
  putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void>;
  getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null>;
  takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null>;
  putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void>;
  getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null>;
  takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null>;
  putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  getCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  takeCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  putFinalizeReplay(replay: StoredWalletRegistrationFinalizeReplay): Promise<void>;
  getFinalizeReplay(input: {
    registrationCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletRegistrationFinalizeReplay | null>;
  putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  getAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
  updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  takeAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
  putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void>;
  getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null>;
  updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void>;
  takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null>;
}

export class MemoryRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly serverAllocatedWalletReservations = new Map<string, number>();
  private readonly intents = new Map<string, StoredRegistrationIntent>();
  private readonly preparations = new Map<string, StoredWalletRegistrationHssPreparation>();
  private readonly addAuthMethodIntents = new Map<string, StoredAddAuthMethodIntent>();
  private readonly addSignerIntents = new Map<string, StoredAddSignerIntent>();
  private readonly ceremonies = new Map<string, StoredWalletRegistrationCeremony>();
  private readonly finalizeReplays = new Map<string, StoredWalletRegistrationFinalizeReplay>();
  private readonly addAuthMethodCeremonies = new Map<string, StoredWalletAddAuthMethodCeremony>();
  private readonly addSignerCeremonies = new Map<string, StoredWalletAddSignerCeremony>();

  async reserveServerAllocatedWalletId(input: {
    walletId: ServerAllocatedWalletId;
    expiresAtMs: number;
  }): Promise<boolean> {
    this.pruneExpired();
    const reservationId = serverAllocatedWalletReservationKey(input);
    const expiresAtMs = Number(input.expiresAtMs);
    if (!reservationId || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      return false;
    }
    if (this.serverAllocatedWalletReservations.has(reservationId)) return false;
    this.serverAllocatedWalletReservations.set(reservationId, expiresAtMs);
    return true;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    this.pruneExpired();
    this.intents.set(intent.grant, intent);
  }

  async getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null> {
    this.pruneExpired();
    const intent = this.intents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.intents.get(key) || null;
    if (!intent) return null;
    this.intents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() };
  }

  async consumeRegistrationIntentForPreparation(
    input: ConsumeRegistrationIntentForPreparationInput,
  ): Promise<ConsumeRegistrationIntentForPreparationResult> {
    this.pruneExpired();
    const grantKey = String(input.registrationIntentGrant || '').trim();
    const intent = this.intents.get(grantKey) || null;
    if (
      !intent ||
      intent.expiresAtMs <= Date.now() ||
      intent.digestB64u !== input.registrationIntentDigestB64u
    ) {
      return {
        ok: false,
        code: 'invalid_grant',
        message: 'registration intent grant expired',
      };
    }
    const preparation =
      this.preparations.get(String(input.registrationPreparationId || '').trim()) || null;
    if (
      !preparation ||
      preparation.expiresAtMs <= Date.now() ||
      !registrationPreparationMatchesIntentConsume(preparation, input)
    ) {
      return {
        ok: false,
        code: 'scope_mismatch',
        message: 'registration preparation scope does not match verified intent',
      };
    }
    this.intents.delete(grantKey);
    return {
      ok: true,
      intent: { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() },
    };
  }

  async putPreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    this.pruneExpired();
    const parsed = parseStoredWalletRegistrationHssPreparation(preparation);
    if (!parsed) throw new Error('Invalid wallet registration preparation record');
    this.preparations.set(parsed.registrationPreparationId, parsed);
  }

  async getPreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    this.pruneExpired();
    const preparation =
      this.preparations.get(String(registrationPreparationId || '').trim()) || null;
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async updatePreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    this.pruneExpired();
    const parsed = parseStoredWalletRegistrationHssPreparation(preparation);
    if (!parsed) throw new Error('Invalid wallet registration preparation record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const key = String(parsed.registrationPreparationId || '').trim();
    if (!this.preparations.has(key)) return;
    this.preparations.set(key, parsed);
  }

  async takePreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    this.pruneExpired();
    const key = String(registrationPreparationId || '').trim();
    const preparation = this.preparations.get(key) || null;
    this.preparations.delete(key);
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    this.pruneExpired();
    this.addAuthMethodIntents.set(intent.grant, intent);
  }

  async getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null> {
    this.pruneExpired();
    const intent = this.addAuthMethodIntents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.addAuthMethodIntents.get(key) || null;
    if (!intent) return null;
    this.addAuthMethodIntents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_auth_method_intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    this.pruneExpired();
    this.addSignerIntents.set(intent.grant, intent);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    this.pruneExpired();
    const intent = this.addSignerIntents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.addSignerIntents.get(key) || null;
    if (!intent) return null;
    this.addSignerIntents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const ceremony = this.ceremonies.get(String(registrationCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const key = String(registrationCeremonyId || '').trim();
    const ceremony = this.ceremonies.get(key) || null;
    this.ceremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putFinalizeReplay(replay: StoredWalletRegistrationFinalizeReplay): Promise<void> {
    this.pruneExpired();
    const parsed = parseStoredWalletRegistrationFinalizeReplay(replay);
    if (!parsed) throw new Error('Invalid wallet registration finalize replay record');
    this.finalizeReplays.set(finalizeReplayKey(parsed), parsed);
  }

  async getFinalizeReplay(input: {
    registrationCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletRegistrationFinalizeReplay | null> {
    this.pruneExpired();
    const replay =
      this.finalizeReplays.get(
        finalizeReplayKey({
          registrationCeremonyId: input.registrationCeremonyId,
          idempotencyKey: input.idempotencyKey,
        }),
      ) || null;
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    this.pruneExpired();
    this.addAuthMethodCeremonies.set(ceremony.addAuthMethodCeremonyId, ceremony);
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    this.pruneExpired();
    const ceremony =
      this.addAuthMethodCeremonies.get(String(addAuthMethodCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.addAuthMethodCeremonies.set(ceremony.addAuthMethodCeremonyId, ceremony);
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    this.pruneExpired();
    const key = String(addAuthMethodCeremonyId || '').trim();
    const ceremony = this.addAuthMethodCeremonies.get(key) || null;
    this.addAuthMethodCeremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const ceremony = this.addSignerCeremonies.get(String(addSignerCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const key = String(addSignerCeremonyId || '').trim();
    const ceremony = this.addSignerCeremonies.get(key) || null;
    this.addSignerCeremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, intent] of this.intents) {
      if (intent.expiresAtMs <= now) this.intents.delete(key);
    }
    for (const [key, preparation] of this.preparations) {
      if (preparation.expiresAtMs <= now) this.preparations.delete(key);
    }
    for (const [key, intent] of this.addAuthMethodIntents) {
      if (intent.expiresAtMs <= now) this.addAuthMethodIntents.delete(key);
    }
    for (const [key, intent] of this.addSignerIntents) {
      if (intent.expiresAtMs <= now) this.addSignerIntents.delete(key);
    }
    for (const [key, ceremony] of this.ceremonies) {
      if (ceremony.expiresAtMs <= now) this.ceremonies.delete(key);
    }
    for (const [key, replay] of this.finalizeReplays) {
      if (replay.expiresAtMs <= now) this.finalizeReplays.delete(key);
    }
    for (const [key, ceremony] of this.addAuthMethodCeremonies) {
      if (ceremony.expiresAtMs <= now) this.addAuthMethodCeremonies.delete(key);
    }
    for (const [key, ceremony] of this.addSignerCeremonies) {
      if (ceremony.expiresAtMs <= now) this.addSignerCeremonies.delete(key);
    }
    for (const [key, expiresAtMs] of this.serverAllocatedWalletReservations) {
      if (expiresAtMs <= now) this.serverAllocatedWalletReservations.delete(key);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function serverAllocatedWalletReservationKey(input: { walletId: ServerAllocatedWalletId }): string {
  const walletId = trimString(input.walletId);
  if (!walletId) return '';
  return walletId;
}

function finalizeReplayKey(input: {
  registrationCeremonyId: string;
  idempotencyKey: string;
}): string {
  return `${trimString(input.registrationCeremonyId)}:${trimString(input.idempotencyKey)}`;
}

function parseJsonValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseWalletRegistrationFinalizeAuthMethod(
  value: unknown,
): WalletRegistrationFinalizeAuthMethod | null {
  if (!isRecord(value)) return null;
  switch (value.kind) {
    case 'passkey': {
      const credentialIdB64u = trimString(value.credentialIdB64u);
      const credentialPublicKeyB64u = trimString(value.credentialPublicKeyB64u);
      if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
      return {
        kind: 'passkey',
        credentialIdB64u,
        credentialPublicKeyB64u,
      };
    }
    case 'email_otp': {
      const registrationAuthorityId = trimString(value.registrationAuthorityId);
      if (!registrationAuthorityId) return null;
      return {
        kind: 'email_otp',
        registrationAuthorityId,
      };
    }
    default:
      return null;
  }
}

function parseFinalizeReplayResponse(
  value: unknown,
): Extract<WalletRegistrationFinalizeResponse, { ok: true }> | null {
  if (!isRecord(value) || value.ok !== true) return null;
  const walletIdRaw = trimString(value.walletId);
  const rpId = trimString(value.rpId);
  if (!walletIdRaw) return null;
  const walletId = walletIdFromString(walletIdRaw);
  if (value.kind === 'already_finalized_restore_required') {
    if (value.reason !== 'replay_without_session_material') return null;
    return {
      ok: true,
      kind: 'already_finalized_restore_required',
      walletId,
      ...(rpId ? { rpId } : {}),
      reason: 'replay_without_session_material',
    };
  }
  const authMethod = parseWalletRegistrationFinalizeAuthMethod(value.authMethod);
  const authority = parseWalletAuthAuthority(value.authority);
  if (!authMethod || !authority || authority.walletId !== walletId) return null;
  const authorityScope = parseThresholdEd25519AuthorityScope(value.authorityScope);
  let ed25519: Extract<WalletRegistrationFinalizeResponse, { ok: true }>['ed25519'];
  const accountProvisioning = isRecord(value.accountProvisioning)
    ? (value.accountProvisioning as Extract<
        WalletRegistrationFinalizeResponse,
        { ok: true; ed25519: unknown }
      >['accountProvisioning'])
    : undefined;
  const resolvedAccount = isRecord(value.resolvedAccount)
    ? (value.resolvedAccount as Extract<
        WalletRegistrationFinalizeResponse,
        { ok: true; ed25519: unknown }
      >['resolvedAccount'])
    : undefined;
  if (value.ed25519 !== undefined) {
    if (!isRecord(value.ed25519) || value.ed25519.session !== undefined) return null;
    const nearAccountId = trimString(value.ed25519.nearAccountId);
    const nearEd25519SigningKeyId = trimString(value.ed25519.nearEd25519SigningKeyId);
    const publicKey = trimString(value.ed25519.publicKey);
    const relayerKeyId = trimString(value.ed25519.relayerKeyId);
    const keyVersion = trimString(value.ed25519.keyVersion);
    if (
      !nearAccountId ||
      !nearEd25519SigningKeyId ||
      !publicKey ||
      !relayerKeyId ||
      !keyVersion ||
      value.ed25519.recoveryExportCapable !== true
    ) {
      return null;
    }
    const clientParticipantId = Number(value.ed25519.clientParticipantId);
    const relayerParticipantId = Number(value.ed25519.relayerParticipantId);
    const participantIds = Array.isArray(value.ed25519.participantIds)
      ? value.ed25519.participantIds.map((id) => Number(id))
      : undefined;
    if (participantIds && participantIds.some((id) => !Number.isSafeInteger(id))) return null;
    ed25519 = {
      nearAccountId,
      nearEd25519SigningKeyId,
      publicKey,
      relayerKeyId,
      keyVersion,
      recoveryExportCapable: true,
      ...(Number.isSafeInteger(clientParticipantId) ? { clientParticipantId } : {}),
      ...(Number.isSafeInteger(relayerParticipantId) ? { relayerParticipantId } : {}),
      ...(participantIds ? { participantIds } : {}),
    };
  }
  let ecdsa: Extract<WalletRegistrationFinalizeResponse, { ok: true }>['ecdsa'];
  if (value.ecdsa !== undefined) {
    if (!isRecord(value.ecdsa) || !Array.isArray(value.ecdsa.walletKeys)) return null;
    ecdsa = {
      walletKeys: value.ecdsa.walletKeys as WalletRegistrationEcdsaWalletKey[],
    };
  }
  if (ed25519 && (!accountProvisioning || !resolvedAccount)) return null;
  if (ed25519) {
    if (
      !authorityScope ||
      !thresholdEd25519AuthorityScopesMatch(
        authorityScope,
        thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
      )
    ) {
      return null;
    }
    return {
      ok: true,
      walletId,
      ...(rpId ? { rpId } : {}),
      authority,
      authorityScope,
      authMethod,
      accountProvisioning: accountProvisioning!,
      resolvedAccount: resolvedAccount!,
      ed25519,
      ...(ecdsa ? { ecdsa } : {}),
    };
  }
  if (ecdsa) {
    return {
      ok: true,
      walletId,
      ...(rpId ? { rpId } : {}),
      authority,
      authMethod,
      ecdsa,
    };
  }
  return null;
}

function parseStoredWalletRegistrationFinalizeReplay(
  value: unknown,
): StoredWalletRegistrationFinalizeReplay | null {
  value = parseJsonValue(value);
  if (!isRecord(value) || value.kind !== 'wallet_registration_finalize_replay_v1') return null;
  const registrationCeremonyId = trimString(value.registrationCeremonyId);
  const idempotencyKey = trimString(value.idempotencyKey);
  const createdAtMs = Number(value.createdAtMs);
  const expiresAtMs = Number(value.expiresAtMs);
  const response = parseFinalizeReplayResponse(value.response);
  if (
    !registrationCeremonyId ||
    !idempotencyKey ||
    !response ||
    !Number.isSafeInteger(createdAtMs) ||
    createdAtMs <= 0 ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_registration_finalize_replay_v1',
    registrationCeremonyId,
    idempotencyKey,
    response,
    createdAtMs,
    expiresAtMs,
  };
}

function parseStoredRegistrationIntent(value: unknown): StoredRegistrationIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'intent_allocated') return null;
  if (typeof value.grant !== 'string' || !value.grant.trim()) return null;
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  return value as StoredRegistrationIntent;
}

function parseStoredBase64Url(value: unknown): string {
  const parsed = trimString(value);
  if (!parsed) return '';
  try {
    base64UrlDecode(parsed);
    return parsed;
  } catch {
    return '';
  }
}

function parseStoredThresholdEd25519ParticipantIds(value: unknown): number[] | null {
  if (!Array.isArray(value) || value.length < 2) return null;
  const participantIds: number[] = [];
  for (const item of value) {
    const participantId = Number(item);
    if (!Number.isSafeInteger(participantId) || participantId <= 0) return null;
    participantIds.push(participantId);
  }
  return participantIds;
}

function parseStoredThresholdEd25519HssCanonicalContext(
  value: unknown,
): ThresholdEd25519HssCanonicalContext | null {
  if (!isRecord(value)) return null;
  const applicationBindingDigestB64u = parseStoredBase64Url(value.applicationBindingDigestB64u);
  const participantIds = parseStoredThresholdEd25519ParticipantIds(value.participantIds);
  if (!applicationBindingDigestB64u || !participantIds) return null;
  if (base64UrlDecode(applicationBindingDigestB64u).byteLength !== 32) return null;
  return {
    applicationBindingDigestB64u,
    participantIds,
  };
}

function parseStoredThresholdEd25519HssPreparedServerSession(
  value: unknown,
): ThresholdEd25519HssPersistedPreparedServerSession | null {
  if (!isRecord(value)) return null;
  const evaluatorDriverStateB64u = parseStoredBase64Url(value.evaluatorDriverStateB64u);
  const garblerDriverStateB64u = parseStoredBase64Url(value.garblerDriverStateB64u);
  if (!evaluatorDriverStateB64u || !garblerDriverStateB64u) return null;
  return {
    evaluatorDriverStateB64u,
    garblerDriverStateB64u,
  };
}

function parseStoredThresholdEd25519HssRespondedServerSession(
  value: unknown,
): ThresholdEd25519HssPersistedRespondedServerSession | null {
  const prepared = parseStoredThresholdEd25519HssPreparedServerSession(value);
  if (!prepared || !isRecord(value)) return null;
  const serverEvalStateB64u = parseStoredBase64Url(value.serverEvalStateB64u);
  if (!serverEvalStateB64u) return null;
  return {
    ...prepared,
    serverEvalStateB64u,
  };
}

function parseStoredThresholdEd25519HssServerInputs(
  value: unknown,
): ThresholdEd25519HssPersistedServerInputs | null {
  if (!isRecord(value)) return null;
  const yRelayerB64u = parseStoredBase64Url(value.yRelayerB64u);
  const tauRelayerB64u = parseStoredBase64Url(value.tauRelayerB64u);
  if (!yRelayerB64u || !tauRelayerB64u) return null;
  return {
    yRelayerB64u,
    tauRelayerB64u,
  };
}

function parseStoredThresholdEd25519HssPreparedServerState(
  value: unknown,
): ThresholdEd25519HssRegistrationPreparedServerState | null {
  if (!isRecord(value)) return null;
  const context = parseStoredThresholdEd25519HssCanonicalContext(value.context);
  const preparedServerSession = parseStoredThresholdEd25519HssPreparedServerSession(
    value.preparedServerSession,
  );
  const serverInputs = parseStoredThresholdEd25519HssServerInputs(value.serverInputs);
  if (!context || !preparedServerSession || !serverInputs) return null;
  return {
    context,
    preparedServerSession,
    serverInputs,
  };
}

function parseStoredThresholdEd25519HssRespondedServerState(
  value: unknown,
): ThresholdEd25519HssRegistrationRespondedServerState | null {
  if (!isRecord(value)) return null;
  const context = parseStoredThresholdEd25519HssCanonicalContext(value.context);
  const preparedServerSession = parseStoredThresholdEd25519HssRespondedServerSession(
    value.preparedServerSession,
  );
  if (!context || !preparedServerSession || hasDefinedField(value, 'serverInputs')) return null;
  return {
    context,
    preparedServerSession,
  };
}

function parseStoredEd25519RegistrationPrepared(
  value: unknown,
): StoredEd25519RegistrationPrepared | null {
  if (!isRecord(value) || value.kind !== 'ed25519_prepared') return null;
  const ceremonyHandle = trimString(value.ceremonyHandle);
  const clientOtOfferMessageB64u = trimString(value.clientOtOfferMessageB64u);
  const serverState = parseStoredThresholdEd25519HssPreparedServerState(value.serverState);
  if (!ceremonyHandle || !clientOtOfferMessageB64u || !isRecord(value.preparedSession)) {
    return null;
  }
  if (!serverState) return null;
  const contextBindingB64u = trimString(value.preparedSession.contextBindingB64u);
  const evaluatorDriverStateB64u = trimString(value.preparedSession.evaluatorDriverStateB64u);
  if (!contextBindingB64u || !evaluatorDriverStateB64u) return null;
  return {
    kind: 'ed25519_prepared',
    ceremonyHandle,
    preparedSession: {
      contextBindingB64u,
      evaluatorDriverStateB64u,
    },
    clientOtOfferMessageB64u,
    serverState,
  };
}

function parseRegistrationEd25519AuthorityScope(
  value: unknown,
): RegistrationEd25519AuthorityScope | null {
  if (!isRecord(value)) return null;
  const kind = trimString(value.kind);
  switch (kind) {
    case 'passkey': {
      const rpId = parseWebAuthnRpId(value.rpId);
      return rpId.ok ? { kind: 'passkey', rpId: rpId.value } : null;
    }
    case 'email_otp': {
      const provider = trimString(value.provider);
      const providerUserId = parseEmailOtpProviderUserId(value.providerUserId);
      if (
        (provider !== 'google' && provider !== 'email') ||
        !providerUserId.ok ||
        trimString(value.email) ||
        trimString(value.proofKind) ||
        trimString(value.challengeId) ||
        trimString(value.googleEmailOtpRegistrationAttemptId) ||
        trimString(value.googleEmailOtpRegistrationOfferId) ||
        trimString(value.googleEmailOtpRegistrationCandidateId)
      ) {
        return null;
      }
      return { kind: 'email_otp', provider, providerUserId: providerUserId.value };
    }
    default:
      return null;
  }
}

function parseStoredEd25519RegistrationPrepareScope(
  value: unknown,
): StoredEd25519RegistrationPrepareScope | null {
  if (!isRecord(value)) return null;
  const walletId = trimString(value.walletId);
  const authorityScope = parseRegistrationEd25519AuthorityScope(value.authorityScope);
  const registrationIntentDigestB64u = trimString(value.registrationIntentDigestB64u);
  const expectedOrigin = trimString(value.expectedOrigin);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const signingRootId = trimString(value.signingRootId);
  const signingRootVersion = trimString(value.signingRootVersion);
  const nearEd25519SigningKeyId = trimString(value.nearEd25519SigningKeyId);
  const signerSlot = Number(value.signerSlot);
  const keyPurpose = trimString(value.keyPurpose);
  const keyVersion = trimString(value.keyVersion);
  const derivationVersion = Number(value.derivationVersion);
  const participantIds = Array.isArray(value.participantIds)
    ? value.participantIds.map((id) => Number(id))
    : [];
  if (
    !walletId ||
    !authorityScope ||
    !registrationIntentDigestB64u ||
    orgId === null ||
    !signingRootVersion ||
    !nearEd25519SigningKeyId ||
    !Number.isSafeInteger(signerSlot) ||
    signerSlot < 1 ||
    !keyPurpose ||
    !keyVersion ||
    !Number.isSafeInteger(derivationVersion) ||
    participantIds.length === 0 ||
    participantIds.some((id) => !Number.isSafeInteger(id))
  ) {
    return null;
  }
  return {
    walletId,
    authorityScope,
    registrationIntentDigestB64u,
    expectedOrigin,
    orgId,
    signingRootId,
    signingRootVersion,
    nearEd25519SigningKeyId,
    signerSlot,
    keyPurpose,
    keyVersion,
    derivationVersion,
    participantIds,
  };
}

function parseStoredWalletRegistrationHssPreparationBase(
  value: unknown,
): StoredWalletRegistrationHssPreparationBase | null {
  if (!isRecord(value)) return null;
  const registrationPreparationId = trimString(value.registrationPreparationId);
  const registrationIntentGrant = trimString(value.registrationIntentGrant);
  const registrationIntentDigestB64u = trimString(value.registrationIntentDigestB64u);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const expectedOrigin = trimString(value.expectedOrigin);
  const signingRootId = trimString(value.signingRootId);
  const signingRootVersion = trimString(value.signingRootVersion);
  const createdAtMs = Number(value.createdAtMs);
  const expiresAtMs = Number(value.expiresAtMs);
  const intentRecord = parseStoredRegistrationIntent({
    kind: 'intent_allocated',
    grant: registrationIntentGrant,
    intent: value.intent,
    digestB64u: registrationIntentDigestB64u,
    orgId: orgId || '',
    signingRootId,
    signingRootVersion,
    expectedOrigin,
    expiresAtMs,
  });
  const ed25519Scope = parseStoredEd25519RegistrationPrepareScope(value.ed25519Scope);
  const authority = parseStoredRegistrationAuthority(value.authority);
  if (
    !registrationPreparationId ||
    !registrationIntentGrant ||
    !registrationIntentDigestB64u ||
    orgId === null ||
    !signingRootVersion ||
    !Number.isSafeInteger(createdAtMs) ||
    createdAtMs <= 0 ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    !intentRecord ||
    !authority ||
    !ed25519Scope
  ) {
    return null;
  }
  return {
    registrationPreparationId: registrationPreparationId as RegistrationPreparationId,
    registrationIntentGrant: registrationIntentGrant as RegistrationIntentGrant,
    registrationIntentDigestB64u,
    intent: intentRecord.intent,
    authority,
    orgId,
    expectedOrigin,
    signingRootId,
    signingRootVersion,
    ed25519Scope,
    createdAtMs,
    expiresAtMs,
  };
}

function parseStoredWalletRegistrationHssPreparationFailure(
  value: unknown,
): StoredWalletRegistrationHssPreparationFailed['failure'] | null {
  if (!isRecord(value)) return null;
  const code = trimString(value.code);
  const message = trimString(value.message);
  if (!code || !message) return null;
  return { code, message };
}

export function parseStoredWalletRegistrationHssPreparation(
  value: unknown,
): StoredWalletRegistrationHssPreparation | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  const base = parseStoredWalletRegistrationHssPreparationBase(value);
  if (!base) return null;
  switch (value.kind) {
    case 'hss_prepare_preparing':
      if (
        hasDefinedField(value, 'prepared') ||
        hasDefinedField(value, 'failure') ||
        hasDefinedField(value, 'consumedAtMs')
      ) {
        return null;
      }
      return buildStoredWalletRegistrationHssPreparationPreparing(base);
    case 'hss_prepare_prepared': {
      if (hasDefinedField(value, 'failure') || hasDefinedField(value, 'consumedAtMs')) {
        return null;
      }
      const prepared = parseStoredEd25519RegistrationPrepared(value.prepared);
      if (!prepared) return null;
      return buildStoredWalletRegistrationHssPreparationPrepared({
        ...base,
        prepared,
      });
    }
    case 'hss_prepare_failed': {
      if (hasDefinedField(value, 'prepared') || hasDefinedField(value, 'consumedAtMs')) {
        return null;
      }
      const failure = parseStoredWalletRegistrationHssPreparationFailure(value.failure);
      if (!failure) return null;
      return buildStoredWalletRegistrationHssPreparationFailed({
        ...base,
        failure,
      });
    }
    default:
      return null;
  }
}

function parseStoredAddSignerIntent(value: unknown): StoredAddSignerIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'add_signer_intent_allocated') return null;
  if (typeof value.grant !== 'string' || !value.grant.trim()) return null;
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  return value as StoredAddSignerIntent;
}

function parseStoredAddAuthMethodIntent(value: unknown): StoredAddAuthMethodIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'add_auth_method_intent_allocated') return null;
  const grant = trimString(value.grant);
  const digestB64u = trimString(value.digestB64u);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const expiresAtMs = Number(value.expiresAtMs);
  if (!grant || !digestB64u || orgId === null || !Number.isFinite(expiresAtMs)) return null;
  const intent = isRecord(value.intent) ? value.intent : null;
  if (!intent) return null;
  const version = trimString(intent.version);
  const walletId = walletIdFromString(trimString(intent.walletId));
  const authMethod = normalizeAddAuthMethodInput(intent.authMethod);
  const nonceB64u = trimString(intent.nonceB64u);
  if (version !== 'add_auth_method_intent_v1' || !walletId || !authMethod || !nonceB64u) {
    return null;
  }
  const parsedIntent: AddAuthMethodIntentV1 = {
    version: 'add_auth_method_intent_v1',
    walletId,
    authMethod,
    nonceB64u,
  };
  if (Object.prototype.hasOwnProperty.call(intent, 'runtimePolicyScope')) {
    const runtimePolicyScope = parseRuntimePolicyScopeLike(intent.runtimePolicyScope);
    if (!runtimePolicyScope) return null;
    parsedIntent.runtimePolicyScope = runtimePolicyScope;
  }
  const normalizedGrant = addAuthMethodIntentGrantFromString(grant);
  if (!normalizedGrant) {
    return null;
  }
  return {
    kind: 'add_auth_method_intent_allocated',
    grant: normalizedGrant,
    intent: parsedIntent,
    digestB64u,
    orgId,
    expiresAtMs: Math.floor(expiresAtMs),
    ...(trimString(value.signingRootId) ? { signingRootId: trimString(value.signingRootId) } : {}),
    ...(trimString(value.signingRootVersion)
      ? { signingRootVersion: trimString(value.signingRootVersion) }
      : {}),
    ...(trimString(value.expectedOrigin)
      ? { expectedOrigin: trimString(value.expectedOrigin) }
      : {}),
  };
}

function hasDefinedField(obj: Record<string, unknown>, field: string): boolean {
  return field in obj && obj[field] !== undefined;
}

function parseRuntimePolicyScopeLike(
  value: unknown,
): AddAuthMethodIntentV1['runtimePolicyScope'] | null {
  if (!isRecord(value)) return null;
  const orgId = trimString(value.orgId);
  const projectId = trimString(value.projectId);
  const envId = trimString(value.envId);
  const signingRootVersion = trimString(value.signingRootVersion);
  if (!orgId || !projectId || !envId) return null;
  if (hasDefinedField(value, 'signingRootVersion') && !signingRootVersion) return null;
  return signingRootVersion
    ? { orgId, projectId, envId, signingRootVersion }
    : { orgId, projectId, envId };
}

function parseStoredRegistrationAuthority(value: unknown): StoredRegistrationAuthority | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  const walletId = parseWalletId(value.walletId);
  const registrationIntentDigestB64u =
    typeof value.registrationIntentDigestB64u === 'string' &&
    value.registrationIntentDigestB64u.trim()
      ? value.registrationIntentDigestB64u
      : null;
  if (!walletId.ok || !registrationIntentDigestB64u) return null;

  switch (value.kind) {
    case 'passkey': {
      if (hasDefinedField(value, 'emailHashHex') || hasDefinedField(value, 'challengeId')) {
        return null;
      }
      const rpId = parseWebAuthnRpId(value.rpId);
      if (!rpId.ok) return null;
      const credentialIdB64u =
        typeof value.credentialIdB64u === 'string' && value.credentialIdB64u.trim()
          ? value.credentialIdB64u
          : null;
      const credentialPublicKeyB64u =
        typeof value.credentialPublicKeyB64u === 'string' && value.credentialPublicKeyB64u.trim()
          ? value.credentialPublicKeyB64u
          : null;
      const counter = Number(value.counter);
      if (!credentialIdB64u || !credentialPublicKeyB64u || !Number.isSafeInteger(counter)) {
        return null;
      }
      return {
        kind: 'passkey',
        walletId: walletId.value,
        rpId: rpId.value,
        credentialIdB64u,
        credentialPublicKeyB64u,
        counter,
        registrationIntentDigestB64u,
      };
    }
    case 'email_otp': {
      if (
        hasDefinedField(value, 'rpId') ||
        hasDefinedField(value, 'credentialIdB64u') ||
        hasDefinedField(value, 'credentialPublicKeyB64u') ||
        hasDefinedField(value, 'counter')
      ) {
        return null;
      }
      const emailHashHex =
        typeof value.emailHashHex === 'string' && value.emailHashHex.trim()
          ? value.emailHashHex
          : null;
      const proofKind = typeof value.proofKind === 'string' ? value.proofKind.trim() : '';
      const providerSubject =
        typeof value.providerSubject === 'string' && value.providerSubject.trim()
          ? value.providerSubject
          : null;
      const email =
        typeof value.email === 'string' && value.email.trim() ? value.email.toLowerCase() : null;
      const parsedProviderSubject = parseProviderSubject(providerSubject);
      const finalWalletId = parseWalletId(value.finalWalletId);
      const orgId = parseOrgId(value.orgId);
      const appSessionVersion = parseAppSessionVersion(value.appSessionVersion);
      if (
        !providerSubject ||
        !email ||
        !emailHashHex ||
        !parsedProviderSubject.ok ||
        !finalWalletId.ok ||
        !orgId.ok ||
        !appSessionVersion.ok
      ) {
        return null;
      }
      if (proofKind === 'otp_challenge') {
        const challengeId =
          typeof value.challengeId === 'string' && value.challengeId.trim()
            ? value.challengeId
            : null;
        const challengeSubjectId = parseChallengeSubjectId(value.challengeSubjectId);
        const parsedChallengeId = parseEmailOtpChallengeId(challengeId);
        const originalWalletId = parseWalletId(value.originalWalletId);
        const challengePurpose =
          value.challengePurpose === 'registration' ||
          value.challengePurpose === 'registration_reroll'
            ? value.challengePurpose
            : null;
        if (
          !challengeId ||
          !challengeSubjectId.ok ||
          !parsedChallengeId.ok ||
          !originalWalletId.ok ||
          !challengePurpose
        ) {
          return null;
        }
        return {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          walletId: walletId.value,
          providerSubject: parsedProviderSubject.value,
          challengeSubjectId: challengeSubjectId.value,
          email,
          emailHashHex,
          challengeId: parsedChallengeId.value,
          registrationAuthorityId: parsedChallengeId.value,
          originalWalletId: originalWalletId.value,
          finalWalletId: finalWalletId.value,
          orgId: orgId.value,
          appSessionVersion: appSessionVersion.value,
          challengePurpose,
          registrationIntentDigestB64u,
        };
      }
      if (proofKind === 'google_sso_registration') {
        const registrationAttemptId =
          typeof value.googleEmailOtpRegistrationAttemptId === 'string' &&
          value.googleEmailOtpRegistrationAttemptId.trim()
            ? value.googleEmailOtpRegistrationAttemptId.trim()
            : '';
        const registrationOfferId =
          typeof value.googleEmailOtpRegistrationOfferId === 'string' &&
          value.googleEmailOtpRegistrationOfferId.trim()
            ? value.googleEmailOtpRegistrationOfferId.trim()
            : '';
        const registrationCandidateId =
          typeof value.googleEmailOtpRegistrationCandidateId === 'string' &&
          value.googleEmailOtpRegistrationCandidateId.trim()
            ? value.googleEmailOtpRegistrationCandidateId.trim()
            : '';
        if (
          !registrationAttemptId ||
          !registrationOfferId ||
          !registrationCandidateId ||
          hasDefinedField(value, 'challengeId') ||
          hasDefinedField(value, 'challengeSubjectId') ||
          hasDefinedField(value, 'originalWalletId') ||
          hasDefinedField(value, 'challengePurpose')
        ) {
          return null;
        }
        return {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          walletId: walletId.value,
          providerSubject: parsedProviderSubject.value,
          email,
          emailHashHex,
          googleEmailOtpRegistrationAttemptId: registrationAttemptId,
          googleEmailOtpRegistrationOfferId: registrationOfferId,
          googleEmailOtpRegistrationCandidateId: registrationCandidateId,
          registrationAuthorityId: registrationAttemptId,
          finalWalletId: finalWalletId.value,
          orgId: orgId.value,
          appSessionVersion: appSessionVersion.value,
          registrationIntentDigestB64u,
        };
      }
      return null;
    }
  }
  return null;
}

function parseStoredWalletRegistrationCeremony(
  value: unknown,
): StoredWalletRegistrationCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.registrationCeremonyId !== 'string' || !value.registrationCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  const authority = parseStoredRegistrationAuthority(value.authority);
  if (!authority || !isRecord(value.signerState)) return null;
  return {
    ...(value as Omit<StoredWalletRegistrationCeremony, 'authority'>),
    authority,
  };
}

function parseStoredWalletAddSignerCeremony(value: unknown): StoredWalletAddSignerCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.addSignerCeremonyId !== 'string' || !value.addSignerCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  if (!isRecord(value.auth) || !isRecord(value.signerState)) return null;
  return value as StoredWalletAddSignerCeremony;
}

function parseAddAuthMethodCeremonyAuth(
  value: unknown,
): StoredWalletAddAuthMethodCeremony['auth'] | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'app_session') {
    return { kind: 'app_session' };
  }
  if (value.kind !== 'webauthn_assertion') return null;
  const rpId = trimString(value.rpId);
  const credentialIdB64u = trimString(value.credentialIdB64u);
  if (!rpId || !credentialIdB64u) return null;
  return {
    kind: 'webauthn_assertion',
    rpId,
    credentialIdB64u,
  };
}

function parseStoredWalletAddAuthMethodCeremony(
  value: unknown,
): StoredWalletAddAuthMethodCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  const addAuthMethodCeremonyId = trimString(value.addAuthMethodCeremonyId);
  const digestB64u = trimString(value.digestB64u);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const expiresAtMs = Number(value.expiresAtMs);
  if (!addAuthMethodCeremonyId || !digestB64u || orgId === null || !Number.isFinite(expiresAtMs)) {
    return null;
  }
  const auth = parseAddAuthMethodCeremonyAuth(value.auth);
  const authority = parseStoredRegistrationAuthority(value.authority);
  const intentRecord = parseStoredAddAuthMethodIntent({
    kind: 'add_auth_method_intent_allocated',
    grant: 'ignored',
    intent: value.intent,
    digestB64u,
    orgId,
    expiresAtMs,
  });
  if (!auth || !authority || !intentRecord) return null;
  return {
    addAuthMethodCeremonyId,
    intent: intentRecord.intent,
    digestB64u,
    orgId,
    expiresAtMs: Math.floor(expiresAtMs),
    auth,
    authority,
    ...(trimString(value.expectedOrigin)
      ? { expectedOrigin: trimString(value.expectedOrigin) }
      : {}),
  };
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'getdel'; key: string }
  | { op: 'authReserveReplayGuard'; key: string; expiresAtMs: number }
  | {
      op: 'getdelIfRelatedMatches';
      key: string;
      relatedKey: string;
      expectedRelated: unknown;
    };

type DoConditionalGetDelResponse = {
  matched: boolean;
  value: unknown | null;
};

function walletRegistrationPreparationConsumeExpectedRecord(
  input: ConsumeRegistrationIntentForPreparationInput,
): Record<string, unknown> {
  return {
    kind: 'hss_prepare_prepared',
    registrationIntentGrant: input.registrationIntentGrant,
    registrationIntentDigestB64u: input.registrationIntentDigestB64u,
    ed25519Scope: input.ed25519Scope,
  };
}

function isDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isRecord(value) && typeof value.idFromName === 'function' && typeof value.get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = config.namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const durableObjectNamespace = config.durableObjectNamespace;
  if (isDurableObjectNamespaceLike(durableObjectNamespace)) return durableObjectNamespace;

  const envStyle = config.THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, request: DoRequest): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Registration ceremony DO store HTTP ${response.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(
      `Registration ceremony DO store returned non-JSON response: ${text.slice(0, 200)}`,
    );
  }
  if (!isRecord(json)) {
    throw new Error('Registration ceremony DO store returned invalid JSON shape');
  }
  if (json.ok === true) return json as DoOk<T>;
  const code = trimString(json.code);
  const message = trimString(json.message);
  return {
    ok: false,
    code: code || 'internal',
    message: message || 'Registration ceremony DO store error',
  };
}

class CloudflareDurableObjectRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(
    scope:
      | 'intent'
      | 'preparation'
      | 'add-auth-method-intent'
      | 'add-signer-intent'
      | 'ceremony'
      | 'finalize-replay'
      | 'server-allocated-wallet-reservation'
      | 'add-auth-method'
      | 'add-signer',
    id: string,
  ): string {
    return `${this.prefix}${scope}:${id}`;
  }

  async reserveServerAllocatedWalletId(input: {
    walletId: ServerAllocatedWalletId;
    expiresAtMs: number;
  }): Promise<boolean> {
    const walletId = trimString(input.walletId);
    const expiresAtMs = Math.floor(Number(input.expiresAtMs));
    if (!walletId || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      return false;
    }
    const response = await callDo<{ reserved: true }>(this.stub, {
      op: 'authReserveReplayGuard',
      key: this.key(
        'server-allocated-wallet-reservation',
        serverAllocatedWalletReservationKey(input),
      ),
      expiresAtMs,
    });
    return response.ok;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    const parsed = parseStoredRegistrationIntent(intent);
    if (!parsed) throw new Error('Invalid registration intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredRegistrationIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredRegistrationIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() };
  }

  async consumeRegistrationIntentForPreparation(
    input: ConsumeRegistrationIntentForPreparationInput,
  ): Promise<ConsumeRegistrationIntentForPreparationResult> {
    const grantKey = trimString(input.registrationIntentGrant);
    const preparationKey = trimString(input.registrationPreparationId);
    if (!grantKey || !preparationKey) {
      return {
        ok: false,
        code: 'invalid_grant',
        message: 'registration intent grant expired',
      };
    }
    const response = await callDo<DoConditionalGetDelResponse>(this.stub, {
      op: 'getdelIfRelatedMatches',
      key: this.key('intent', grantKey),
      relatedKey: this.key('preparation', preparationKey),
      expectedRelated: walletRegistrationPreparationConsumeExpectedRecord(input),
    });
    if (!response.ok) {
      return {
        ok: false,
        code: 'invalid_grant',
        message: 'registration intent grant expired',
      };
    }
    if (!response.value.matched) {
      return {
        ok: false,
        code: 'scope_mismatch',
        message: 'registration preparation scope does not match verified intent',
      };
    }
    const intent = parseStoredRegistrationIntent(response.value.value);
    if (
      !intent ||
      intent.expiresAtMs <= Date.now() ||
      intent.digestB64u !== input.registrationIntentDigestB64u
    ) {
      return {
        ok: false,
        code: 'invalid_grant',
        message: 'registration intent grant expired',
      };
    }
    return {
      ok: true,
      intent: { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() },
    };
  }

  async putPreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    const parsed = parseStoredWalletRegistrationHssPreparation(preparation);
    if (!parsed) throw new Error('Invalid wallet registration preparation record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('preparation', parsed.registrationPreparationId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getPreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    const key = trimString(registrationPreparationId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('preparation', key),
    });
    if (!response.ok) return null;
    const preparation = parseStoredWalletRegistrationHssPreparation(response.value);
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async updatePreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    const parsed = parseStoredWalletRegistrationHssPreparation(preparation);
    if (!parsed) throw new Error('Invalid wallet registration preparation record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('preparation', parsed.registrationPreparationId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takePreparation(
    registrationPreparationId: RegistrationPreparationId,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    const key = trimString(registrationPreparationId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('preparation', key),
    });
    if (!response.ok) return null;
    const preparation = parseStoredWalletRegistrationHssPreparation(response.value);
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    const parsed = parseStoredAddSignerIntent(intent);
    if (!parsed) throw new Error('Invalid add-signer intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer-intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    const parsed = parseStoredAddAuthMethodIntent(intent);
    if (!parsed) throw new Error('Invalid add-auth-method intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method-intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-auth-method-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddAuthMethodIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-auth-method-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddAuthMethodIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_auth_method_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putFinalizeReplay(replay: StoredWalletRegistrationFinalizeReplay): Promise<void> {
    const parsed = parseStoredWalletRegistrationFinalizeReplay(replay);
    if (!parsed) throw new Error('Invalid wallet registration finalize replay record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('finalize-replay', finalizeReplayKey(parsed)),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getFinalizeReplay(input: {
    registrationCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletRegistrationFinalizeReplay | null> {
    if (!trimString(input.registrationCeremonyId) || !trimString(input.idempotencyKey)) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('finalize-replay', finalizeReplayKey(input)),
    });
    if (!response.ok) return null;
    const replay = parseStoredWalletRegistrationFinalizeReplay(response.value);
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    const parsed = parseStoredWalletAddAuthMethodCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-auth-method ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method', parsed.addAuthMethodCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const key = trimString(addAuthMethodCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-auth-method', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddAuthMethodCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    const parsed = parseStoredWalletAddAuthMethodCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-auth-method ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method', parsed.addAuthMethodCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const key = trimString(addAuthMethodCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-auth-method', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddAuthMethodCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }
}

function resolveRegistrationDoPrefix(config: Record<string, unknown>): string {
  const explicit =
    trimString(config.WALLET_REGISTRATION_PREFIX) || trimString(config.walletRegistrationPrefix);
  const base = explicit || trimString(config.keyPrefix) || trimString(config.THRESHOLD_PREFIX);
  if (!base) return 'wallet-registration:';
  return base.endsWith(':') ? `${base}wallet-registration:` : `${base}:wallet-registration:`;
}

export function createRegistrationCeremonyStore(
  input: {
    config?: unknown;
    logger?: NormalizedLogger;
    isNode?: boolean;
  } = {},
): RegistrationCeremonyStore {
  const config = (input.config || {}) as Record<string, unknown>;
  const kind = typeof config.kind === 'string' ? config.kind.trim() : '';
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do registration ceremony store selected but no Durable Object namespace was provided (expected config.namespace)',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger?.info(
      '[wallet-registration] Using Cloudflare Durable Object store for registration ceremonies',
    );
    return new CloudflareDurableObjectRegistrationCeremonyStore({
      namespace,
      objectName,
      prefix: resolveRegistrationDoPrefix(config),
    });
  }
  if (kind && kind !== 'memory' && kind !== 'in-memory') {
    throw new Error(`[wallet-registration] Unknown registration ceremony store kind: ${kind}`);
  }
  input.logger?.warn?.(
    '[wallet-registration] Using in-memory registration ceremony store; configure Cloudflare Durable Object storage for durable registration ceremonies',
  );
  return new MemoryRegistrationCeremonyStore();
}

export function createWalletId(): ServerAllocatedWalletId {
  return createServerAllocatedWalletId();
}
