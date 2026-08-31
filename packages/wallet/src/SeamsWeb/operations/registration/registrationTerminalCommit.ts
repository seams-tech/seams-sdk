/**
 * Client-side terminal registration projection and local persistence.
 *
 * Registration orchestration stays in `registration.ts`; this module owns the
 * response projection and the ECDSA wallet/session installation that follows it.
 */

import {
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseVerifiedEmailAddress,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type {
  RegistrationAuthMethodInput,
  WalletEmailOtpEnrollmentMaterialV1,
  WalletId,
} from '@shared/utils/registrationIntent';
import type { WalletCustodyCeremonyCommitPayload } from '@shared/passkey-custody';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import type {
  WalletRegistrationActivateResponseV2,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationFinalizeResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  assertRegistrationEcdsaSessionMatchesWalletKeys,
  assertRegistrationWalletKeyCapabilities,
  assertSharedRegistrationEvmFamilyWalletKeyMaterial,
  registrationChainTargetListsMatch,
  type RegistrationEcdsaSession,
  type RegistrationLocalEcdsaWalletKeys,
} from './registrationStrictEcdsa';
import type { RegistrationPasskeyAuthority } from './registrationEd25519Yao';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import { persistActiveWalletSessionAuthorizationFromDirectRegistration } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
import {
  buildEmailOtpAuthContext,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  isEmailOtpWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { RegistrationTimingRecorder, assertNever, roundDurationMs } from './registrationTiming';
import {
  parsePendingWalletRegistrationCommitV1,
  type PendingWalletRegistrationCommitAuthV1,
  type PendingWalletRegistrationCommitV1,
  type PendingWalletRegistrationLocalMaterialV1,
} from '@/core/indexedDB/pendingWalletRegistrationCommit';

export function requireWebAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export function requireFinalizedPasskeyCredentialPublicKeyB64u(args: {
  finalized: WalletRegistrationFinalizeResponse;
  credential: WebAuthnRegistrationCredential;
}): string {
  const authMethod = args.finalized.authMethod;
  if (!authMethod || authMethod.kind !== 'passkey') {
    throw new Error('Passkey registration finalize returned non-passkey auth material');
  }
  const localCredentialId = String(args.credential.rawId || args.credential.id || '').trim();
  const returnedCredentialId = String(authMethod.credentialIdB64u || '').trim();
  if (!localCredentialId || returnedCredentialId !== localCredentialId) {
    throw new Error('Passkey registration finalize returned credential id mismatch');
  }
  const credentialPublicKeyB64u = String(authMethod.credentialPublicKeyB64u || '').trim();
  if (!credentialPublicKeyB64u) {
    throw new Error('Passkey registration finalize returned missing credentialPublicKeyB64u');
  }
  return credentialPublicKeyB64u;
}

async function buildRegistrationEmailOtpAuthContext(args: {
  configs: SeamsConfigsReadonly;
  authority: EmailOtpWalletAuthAuthority;
}): Promise<ThresholdEcdsaEmailOtpAuthContext> {
  const policy = args.configs.signing.emailOtp.authPolicy;
  return buildEmailOtpAuthContext({
    policy,
    retention: 'session',
    reason: 'login',
    authority: args.authority,
  });
}

export type RegistrationPersistenceAuth =
  | {
      kind: 'passkey';
      rpId: string;
      credential: WebAuthnRegistrationCredential;
      credentialPublicKeyB64u: string;
      email?: never;
      registrationAuthorityId?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      registrationAuthorityId: string;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      authority: EmailOtpWalletAuthAuthority;
      rpId?: never;
      credential?: never;
      credentialPublicKeyB64u?: never;
    };

export function registrationPersistenceAuthMethod(
  auth: RegistrationPersistenceAuth,
): RegistrationAuthMethodInput['kind'] {
  switch (auth.kind) {
    case 'passkey':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
    default:
      return assertNever(auth);
  }
}

type RegistrationPersistenceEcdsa = {
  kind: 'evm_family_ecdsa';
  session: RegistrationEcdsaSession;
  walletKeys: readonly [WalletRegistrationEcdsaWalletKey, ...WalletRegistrationEcdsaWalletKey[]];
  expectedChainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
};

export type RegistrationPersistencePlan = {
  kind: 'registration_persistence_plan_v1';
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ecdsa: RegistrationPersistenceEcdsa;
  foundingAuthority: WalletRegistrationFinalizeResponse['foundingAuthority'];
  foundingAuthMethod: WalletRegistrationFinalizeResponse['foundingAuthMethod'];
};

export async function buildRegistrationPersistenceAuth(args: {
  authMethod: RegistrationAuthMethodInput;
  configs: SeamsConfigsReadonly;
  walletId: WalletId;
  finalized: WalletRegistrationFinalizeResponse;
  passkeyAuthority: RegistrationPasskeyAuthority | null;
  email: string;
  providerSubject: string;
  registrationAuthorityId: string;
}): Promise<RegistrationPersistenceAuth> {
  switch (args.authMethod.kind) {
    case 'passkey': {
      if (!args.passkeyAuthority) {
        throw new Error('Passkey registration authority was not collected');
      }
      return {
        kind: 'passkey',
        rpId: args.authMethod.rpId,
        credential: args.passkeyAuthority.credential,
        credentialPublicKeyB64u: requireFinalizedPasskeyCredentialPublicKeyB64u({
          finalized: args.finalized,
          credential: args.passkeyAuthority.credential,
        }),
      };
    }
    case 'email_otp': {
      const email = String(args.email || '').trim();
      const providerSubject = String(args.providerSubject || '').trim();
      const registrationAuthorityId = String(args.registrationAuthorityId || '').trim();
      if (!email || !providerSubject || !registrationAuthorityId) {
        throw new Error('Email OTP registration persistence requires provider identity');
      }
      if (!isEmailOtpWalletAuthAuthority(args.finalized.authority)) {
        throw new Error('Email OTP registration finalize returned a different authority');
      }
      if (args.finalized.foundingAuthMethod.kind !== 'email_otp') {
        throw new Error('Email OTP registration finalize returned a different founding method');
      }
      const authority = parseEmailOtpWalletAuthAuthority({
        ...args.finalized.authority,
        bindingId: args.finalized.foundingAuthMethod.walletAuthMethodId,
      });
      if (!authority) {
        throw new Error('Email OTP registration finalize returned an invalid exact authority');
      }
      return {
        kind: 'email_otp',
        email,
        registrationAuthorityId,
        emailOtpAuthContext: await buildRegistrationEmailOtpAuthContext({
          configs: args.configs,
          authority,
        }),
        authority,
      };
    }
    default:
      return assertNever(args.authMethod);
  }
}

export function buildRegistrationPersistenceEcdsa(args: {
  session: RegistrationEcdsaSession;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  expectedChainTargets: readonly ThresholdEcdsaChainTarget[];
}): RegistrationPersistenceEcdsa {
  const [firstWalletKey, ...remainingWalletKeys] = args.walletKeys;
  const [firstTarget, ...remainingTargets] = args.expectedChainTargets;
  if (!firstWalletKey || !firstTarget) {
    throw new Error('ECDSA registration persistence requires session, key, and target material');
  }
  if (args.walletKeys.length !== args.expectedChainTargets.length) {
    throw new Error(
      'ECDSA registration persistence requires one family session projected to every target',
    );
  }
  if (
    args.session.chainTargets.length !== args.expectedChainTargets.length ||
    !registrationChainTargetListsMatch(args.session.chainTargets, args.expectedChainTargets)
  ) {
    throw new Error('ECDSA registration family session target projection is incomplete');
  }
  assertSharedRegistrationEvmFamilyWalletKeyMaterial(args.walletKeys);
  assertRegistrationWalletKeyCapabilities({
    session: args.session,
    walletKeys: args.walletKeys,
  });
  assertRegistrationEcdsaSessionMatchesWalletKeys({
    session: args.session,
    walletKeys: args.walletKeys,
  });
  return {
    kind: 'evm_family_ecdsa',
    session: args.session,
    walletKeys: [firstWalletKey, ...remainingWalletKeys],
    expectedChainTargets: [firstTarget, ...remainingTargets],
  };
}

export function finalizeResponseViewFromActivatedEcdsa(
  activated: Extract<WalletRegistrationActivateResponseV2, { ok: true; kind: 'evm_family_ecdsa' }>,
): Extract<WalletRegistrationFinalizeResponse, { ok: true; kind: 'evm_family_ecdsa' }> {
  const {
    walletId,
    authority,
    foundingAuthority,
    foundingAuthMethod,
    registrationDiagnostics,
    rpId,
    authMethod,
    custodyKeyManifestDigestB64u,
    ecdsa: activatedEcdsa,
  } = activated;
  const { activation: _activation, bootstrap: _bootstrap, ...ecdsa } = activatedEcdsa;
  const base = {
    ok: true as const,
    walletId,
    authority,
    foundingAuthority,
    foundingAuthMethod,
    ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
    ...(custodyKeyManifestDigestB64u !== undefined ? { custodyKeyManifestDigestB64u } : {}),
    kind: 'evm_family_ecdsa' as const,
    ecdsa,
  };
  if (authMethod.kind === 'passkey') {
    if (!rpId) throw new Error('Passkey activation is missing its relying-party id');
    return { ...base, rpId, authMethod };
  }
  if (rpId !== undefined) {
    throw new Error('Email OTP activation returned a relying-party id');
  }
  return { ...base, authMethod };
}

export function buildRegistrationPersistencePlan(args: {
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ecdsa: RegistrationPersistenceEcdsa;
  foundingAuthority: WalletRegistrationFinalizeResponse['foundingAuthority'];
  foundingAuthMethod: WalletRegistrationFinalizeResponse['foundingAuthMethod'];
}): RegistrationPersistencePlan {
  return {
    kind: 'registration_persistence_plan_v1',
    walletId: args.walletId,
    auth: args.auth,
    ecdsa: args.ecdsa,
    foundingAuthority: args.foundingAuthority,
    foundingAuthMethod: args.foundingAuthMethod,
  };
}

type PendingRegistrationCommitBuilderCommonInput = {
  registrationCeremonyId: string;
  idempotencyKey: string;
  walletId: string;
  walletAuthMethodId: string;
  signedSetup: string;
  auth:
    | {
        kind: 'passkey';
        rpId: string;
        credentialIdB64u: string;
        transports: readonly string[];
      }
    | {
        kind: 'email_otp';
        email: string;
        registrationAuthorityId: string;
        providerSubject: string;
        enrollment: WalletEmailOtpEnrollmentMaterialV1;
      };
  createdAtMs: number;
  updatedAtMs: number;
};

type PendingRegistrationEcdsaLocalMaterialInput = Omit<
  Extract<
    PendingWalletRegistrationLocalMaterialV1,
    { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
  >,
  'custodyCommit'
> & {
  readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
};

type PendingRegistrationEd25519LocalMaterialInput = Omit<
  Extract<PendingWalletRegistrationLocalMaterialV1, { readonly keyFamilies: readonly ['ed25519'] }>,
  'custodyCommit'
> & {
  readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
};

type PendingRegistrationMixedLocalMaterialInput = Omit<
  Extract<
    PendingWalletRegistrationLocalMaterialV1,
    { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
  >,
  'custodyCommit' | 'ed25519'
> & {
  readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
  readonly ed25519: Omit<
    Extract<
      PendingWalletRegistrationLocalMaterialV1,
      { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
    >['ed25519'],
    'custodyCommit'
  > & {
    readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
  };
};

type PendingRegistrationCommitBuilderInput = PendingRegistrationCommitBuilderCommonInput &
  (
    | {
        operation: 'registration_activate';
        signerPlanKind: 'near_ed25519';
        localMaterial: PendingRegistrationEd25519LocalMaterialInput;
      }
    | {
        operation: 'registration_activate';
        signerPlanKind: 'evm_family_ecdsa';
        localMaterial: PendingRegistrationEcdsaLocalMaterialInput;
      }
    | {
        operation: 'registration_activate';
        signerPlanKind: 'near_ed25519_and_evm_family_ecdsa';
        localMaterial: PendingRegistrationMixedLocalMaterialInput;
      }
    | {
        operation: 'near_provisioning';
        signerPlanKind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa';
        localMaterial: PendingRegistrationEd25519LocalMaterialInput;
      }
  );

function buildValidatedPendingRegistrationCommit(raw: unknown): PendingWalletRegistrationCommitV1 {
  const parsed = parsePendingWalletRegistrationCommitV1(raw);
  if (!parsed) throw new Error('pending wallet registration commit is invalid');
  return parsed;
}

export function buildPendingRegistrationCommit(
  args: PendingRegistrationCommitBuilderInput,
): PendingWalletRegistrationCommitV1 {
  const walletId = toWalletId(args.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(args.walletAuthMethodId);
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  const auth = buildPendingRegistrationAuth(args.auth);
  const common = {
    kind: 'pending_wallet_registration_commit_v1' as const,
    registrationCeremonyId: requireCanonicalRegistrationString(
      args.registrationCeremonyId,
      'registrationCeremonyId',
    ),
    idempotencyKey: requireCanonicalRegistrationString(args.idempotencyKey, 'idempotencyKey'),
    walletId,
    walletAuthMethodId: walletAuthMethodId.value,
    signedSetup: requireCanonicalRegistrationString(args.signedSetup, 'signedSetup'),
    auth,
    createdAtMs: args.createdAtMs,
    updatedAtMs: args.updatedAtMs,
  };
  if (args.operation === 'registration_activate') {
    if (args.signerPlanKind === 'near_ed25519') {
      return buildValidatedPendingRegistrationCommit({
        ...common,
        operation: args.operation,
        signerPlanKind: args.signerPlanKind,
        localMaterial: args.localMaterial,
      });
    }
    if (args.signerPlanKind === 'evm_family_ecdsa') {
      return buildValidatedPendingRegistrationCommit({
        ...common,
        operation: args.operation,
        signerPlanKind: args.signerPlanKind,
        localMaterial: args.localMaterial,
      });
    }
    return buildValidatedPendingRegistrationCommit({
      ...common,
      operation: args.operation,
      signerPlanKind: args.signerPlanKind,
      localMaterial: args.localMaterial,
    });
  }
  if (
    args.signerPlanKind !== 'near_ed25519' &&
    args.signerPlanKind !== 'near_ed25519_and_evm_family_ecdsa'
  ) {
    throw new Error('near provisioning requires a NEAR signer plan');
  }
  return buildValidatedPendingRegistrationCommit({
    ...common,
    operation: args.operation,
    signerPlanKind: args.signerPlanKind,
    localMaterial: args.localMaterial,
  });
}

function buildPendingRegistrationAuth(
  authInput:
    | {
        kind: 'passkey';
        rpId: string;
        credentialIdB64u: string;
        transports: readonly string[];
      }
    | {
        kind: 'email_otp';
        email: string;
        registrationAuthorityId: string;
        providerSubject: string;
        enrollment: WalletEmailOtpEnrollmentMaterialV1;
      },
): PendingWalletRegistrationCommitAuthV1 {
  if (authInput.kind === 'passkey') {
    const rpId = requireWebAuthnRpId(authInput.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(authInput.credentialIdB64u);
    if (!credentialIdB64u.ok) throw new Error(credentialIdB64u.error.message);
    return {
      kind: 'passkey',
      rpId,
      credentialIdB64u: credentialIdB64u.value,
      transports: [...authInput.transports],
    };
  }
  const email = parseVerifiedEmailAddress(authInput.email);
  if (!email.ok) throw new Error(email.error.message);
  const registrationAuthorityId = parseEmailOtpChallengeId(authInput.registrationAuthorityId);
  if (!registrationAuthorityId.ok) {
    throw new Error(registrationAuthorityId.error.message);
  }
  const providerSubject = parseEmailOtpProviderUserId(authInput.providerSubject);
  if (!providerSubject.ok) throw new Error(providerSubject.error.message);
  return {
    kind: 'email_otp',
    email: email.value,
    registrationAuthorityId: registrationAuthorityId.value,
    providerSubject: providerSubject.value,
    enrollment: {
      enrollmentSealKeyVersion: requireCanonicalRegistrationString(
        authInput.enrollment.enrollmentSealKeyVersion,
        'enrollment.enrollmentSealKeyVersion',
      ),
      serverSealedFactorCiphertextB64u: requireCanonicalRegistrationString(
        authInput.enrollment.serverSealedFactorCiphertextB64u,
        'enrollment.serverSealedFactorCiphertextB64u',
      ),
      clientUnlockPublicKeyB64u: requireCanonicalRegistrationString(
        authInput.enrollment.clientUnlockPublicKeyB64u,
        'enrollment.clientUnlockPublicKeyB64u',
      ),
      unlockKeyVersion: requireCanonicalRegistrationString(
        authInput.enrollment.unlockKeyVersion,
        'enrollment.unlockKeyVersion',
      ),
    },
  };
}

function requireCanonicalRegistrationString(value: string, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

export async function finalizeRegistrationEcdsaSessions(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<RegistrationLocalEcdsaWalletKeys> {
  args.registrationTiming.record('ecdsaRegistrationTargetCount', args.plan.ecdsa.walletKeys.length);
  const startedAt = performance.now();
  try {
    return await args.context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(args.plan.walletId),
      session: args.plan.ecdsa.session,
      walletKeys: [...args.plan.ecdsa.walletKeys],
    });
  } finally {
    args.registrationTiming.record(
      'ecdsaRegistrationSessionFinalizeMs',
      roundDurationMs(startedAt),
    );
  }
}

async function persistRegistrationEcdsaLocalRecords(args: {
  context: RegistrationWebContext;
  plan: RegistrationPersistencePlan;
  walletKeys: RegistrationLocalEcdsaWalletKeys;
}): Promise<void> {
  if (args.plan.auth.kind === 'passkey') {
    await args.context.signingEngine.finalizeWalletEcdsaRegistration({
      walletId: args.plan.walletId,
      rpId: requireWebAuthnRpId(args.plan.auth.rpId),
      credential: args.plan.auth.credential,
      credentialPublicKeyB64u: args.plan.auth.credentialPublicKeyB64u,
      walletKeys: args.walletKeys,
    });
    return;
  }
  await args.context.signingEngine.storeWalletEmailOtpEcdsaRegistrationData({
    walletId: args.plan.walletId,
    email: args.plan.auth.email,
    registrationAuthorityId: args.plan.auth.registrationAuthorityId,
    authority: args.plan.auth.authority,
    walletKeys: args.walletKeys,
  });
}

async function persistRegistrationEcdsaPlan(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<void> {
  const walletKeys = await finalizeRegistrationEcdsaSessions(args);
  const startedAt = performance.now();
  try {
    await persistRegistrationEcdsaLocalRecords({
      context: args.context,
      plan: args.plan,
      walletKeys,
    });
    await IndexedDBManager.persistFoundingWalletAuthority({
      authority: args.plan.foundingAuthority,
      authMethod: args.plan.foundingAuthMethod,
    });
  } finally {
    args.registrationTiming.record(
      'ecdsaRegistrationLocalRecordPersistenceMs',
      roundDurationMs(startedAt),
    );
  }
  await persistActiveWalletSessionAuthorizationFromDirectRegistration(
    walletSessionAuthorizations,
    args.plan.ecdsa.session.registrationEstablishedSession,
  );
}

function registrationEcdsaPlanPersistenceWork(
  args: Parameters<typeof persistRegistrationEcdsaPlan>[0],
): () => Promise<void> {
  return persistRegistrationEcdsaPlan.bind(undefined, args);
}

export async function commitRegistrationPersistencePlan(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<void> {
  await args.registrationTiming.measure(
    'ecdsaRegistrationPersistenceMs',
    registrationEcdsaPlanPersistenceWork(args),
  );
}
