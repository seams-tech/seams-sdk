import {
  walletAuthAuthoritiesMatch,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { type EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import {
  buildCanonicalEvmFamilyEcdsaSigningCapability,
  buildExactEvmFamilyWalletSessionAuthorization,
  type ExactEvmFamilyWalletSessionAuthorization,
} from '../material/ecdsaSigningCapability';
import { buildPersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  resolveExactWalletAuthAuthority,
  type ActiveWalletAuthMethodV2,
  type OwnerLaneScopeStores,
} from '../identity/ownerLaneScope';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ActiveEcdsaCapabilityRuntimeResolver } from '../material/activeEcdsaCapabilityRuntime';

type ExactSelectedWalletAuthority = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
> & {
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly authority: ActiveWalletAuthorityV1;
};

function isExactSelectedWalletAuthority(
  selected: ResolveSelectedWalletAuthorityResultV1,
): selected is ExactSelectedWalletAuthority {
  return (
    selected.kind === 'resolved' &&
    selected.authMethod.status === 'active' &&
    selected.authority.state === 'active'
  );
}

export type EmailOtpEcdsaSigningSessionAuthorityPorts = {
  readonly resolveActiveEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
  readonly factorStores: OwnerLaneScopeStores;
  readonly resolveSelectedWalletAuthority: (
    walletId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  readonly readExactWalletSessionAuthorization: (input: {
    walletId: WalletId;
    authorityId: ActiveWalletAuthorityV1['authorityId'];
    authMethodId: ActiveWalletAuthMethodV2['walletAuthMethodId'];
  }) => Promise<WalletSessionAuthorizationExactOperationCredentialReadResult>;
};

export function emailOtpEcdsaSigningSessionAuthLane(
  authorization: ExactEvmFamilyWalletSessionAuthorization,
): Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ecdsa' }> {
  if (
    authorization.selectedAuthMethod.kind !== 'email_otp' ||
    authorization.runtime.kind !== 'exact_ecdsa_sealed_runtime_v1' ||
    authorization.runtime.authBinding.kind !== 'email_otp' ||
    authorization.operationCredential.token.trim().length === 0 ||
    authorization.runtime.sealedRecord.thresholdSessionId.trim().length === 0
  ) {
    throw new Error('Exact Email OTP ECDSA signing-session authorization is incomplete');
  }
  return {
    kind: 'signing_session',
    operationCredential: authorization.operationCredential,
    thresholdSessionId: authorization.runtime.sealedRecord.thresholdSessionId,
    curve: 'ecdsa',
    chainTarget: authorization.runtime.chainTarget,
  };
}

/**
 * The sealed runtime and capability manifest identify the material and Email
 * OTP authority. The selected authority and exact Wallet Session record must
 * reproduce that tuple before the signing-session lane can be built.
 */
export async function resolveExactEmailOtpEcdsaSigningSessionAuthority(
  ports: EmailOtpEcdsaSigningSessionAuthorityPorts,
  args: {
    readonly walletId: WalletId;
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly manifest: ActiveEcdsaCapabilityManifest;
    readonly runtime: ExactEcdsaSealedRuntime;
  },
): Promise<ExactEvmFamilyWalletSessionAuthorization | null> {
  if (
    args.runtime.kind !== 'exact_ecdsa_sealed_runtime_v1' ||
    args.runtime.walletId !== args.walletId ||
    !thresholdEcdsaChainTargetsEqual(args.runtime.chainTarget, args.chainTarget) ||
    !mpcMaterialActivationRefsEqual(
      args.runtime.materialActivation,
      args.manifest.activation.materialActivation,
    ) ||
    args.manifest.signer.walletId !== args.walletId
  ) {
    return null;
  }
  if (args.runtime.authBinding.kind !== 'email_otp') return null;

  let runtimeAuthorityRef: Awaited<ReturnType<typeof walletAuthAuthorityRef>>;
  try {
    runtimeAuthorityRef = await walletAuthAuthorityRef({
      authority: args.runtime.authBinding.emailOtpAuthority,
    });
  } catch {
    return null;
  }
  const manifestAuthorityRef = args.manifest.signer.authority;
  if (
    runtimeAuthorityRef.walletId !== args.walletId ||
    runtimeAuthorityRef.walletAuthMethodId !== manifestAuthorityRef.walletAuthMethodId ||
    runtimeAuthorityRef.authorityDigest !== manifestAuthorityRef.authorityDigest ||
    manifestAuthorityRef.walletId !== args.walletId
  ) {
    return null;
  }

  let selected: ResolveSelectedWalletAuthorityResultV1;
  try {
    selected = await ports.resolveSelectedWalletAuthority(String(args.walletId));
  } catch {
    return null;
  }
  if (!isExactSelectedWalletAuthority(selected)) return null;
  const { selection, authMethod, authority } = selected;
  const ecdsaActivation = authority.signerActivations.ecdsa;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== args.walletId ||
    authMethod.kind !== 'email_otp' ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== args.walletId ||
    authority.state !== 'active' ||
    authority.walletId !== args.walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.walletAuthMethodId !== runtimeAuthorityRef.walletAuthMethodId ||
    !ecdsaActivation ||
    ecdsaActivation.signer.walletId !== args.walletId ||
    !mpcMaterialActivationRefsEqual(
      ecdsaActivation.materialActivation,
      args.runtime.materialActivation,
    )
  ) {
    return null;
  }

  let selectedFactorAuthority: WalletAuthAuthority;
  try {
    selectedFactorAuthority = await resolveExactWalletAuthAuthority({
      authMethod,
      stores: ports.factorStores,
    });
  } catch {
    return null;
  }
  if (
    !walletAuthAuthoritiesMatch(selectedFactorAuthority, args.runtime.authBinding.emailOtpAuthority)
  ) {
    return null;
  }

  let authorizationRead: Awaited<ReturnType<typeof ports.readExactWalletSessionAuthorization>>;
  try {
    authorizationRead = await ports.readExactWalletSessionAuthorization({
      walletId: args.walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    });
  } catch {
    return null;
  }
  if (authorizationRead.kind !== 'found') return null;
  const { record, operationCredential } = authorizationRead;
  if (
    record.walletId !== args.walletId ||
    record.authorityId !== authority.authorityId ||
    record.authMethodId !== authMethod.walletAuthMethodId ||
    record.authorityDigestB64u !== authority.authorityDigestB64u ||
    record.authorityRevocationEpoch !== authority.revocationEpoch ||
    record.expiresAtMs <= Date.now() ||
    operationCredential.walletSessionId.trim().length === 0 ||
    operationCredential.token.trim().length === 0
  ) {
    return null;
  }
  const signSubjects = record.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ecdsa_secp256k1' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.runtime.materialActivation),
  );
  if (signSubjects.length !== 1) return null;

  try {
    const capability = await buildCanonicalEvmFamilyEcdsaSigningCapability({
      authority: args.runtime.authBinding.emailOtpAuthority,
      manifest: args.manifest,
      material: buildPersistedEcdsaRoleLocalMaterial({
        authority: args.manifest.signer.authority,
        materialActivation: args.manifest.activation.materialActivation,
        publicFacts: args.manifest.durableMaterial.roleLocalPublicFacts,
      }),
    });
    return buildExactEvmFamilyWalletSessionAuthorization({
      capability,
      selected,
      session: record,
      operationCredential,
      runtime: args.runtime,
      nowMs: Date.now(),
    });
  } catch {
    return null;
  }
}
