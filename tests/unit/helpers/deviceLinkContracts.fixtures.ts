import {
  buildLinkedDeviceApprovalV1,
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '../../../packages/shared-ts/src/device-linking/parsers';
import {
  buildExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '../../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import {
  LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionV1,
} from '../../../packages/shared-ts/src/device-linking/sourceContribution';
import { routerAbMpcMaterialActivationRefToWire } from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { requireRouterAbEcdsaDerivationNormalSigningStateV1 } from '../../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceApprovedTargetFactorV1,
  LinkedDeviceOrdinaryMaterialSourceContributionV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  LinkedDeviceTargetFactorV1,
  QrLinkedDeviceSessionPayloadV5,
} from '../../../packages/shared-ts/src/device-linking/contracts';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
} from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import type { WalletKeyId } from '../../../packages/shared-ts/src/signing-lanes/ids';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  parseWalletAuthMethodId,
  parseWalletId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import type {
  MpcMaterialActivationRef,
  WalletAuthMethodId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseEd25519PublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import {
  parseDigestB64u,
  type DigestB64u,
} from '../../../packages/shared-ts/src/utils/canonicalPrimitives';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const FIXTURE_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(8));

function buildR103EcdsaActivation(suffix: string) {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activationId: `activation:r103-${suffix}`,
    capability: 'capability:r103',
    materialOwner: 'wallet:r103',
    keyBinding: `key-binding:r103-${suffix}`,
    lifecycleBinding: `lifecycle:r103-${suffix}`,
    signingWorker: 'worker:r103',
  };
}

export type R103DeviceLinkFixture = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly claimRequest: ReturnType<typeof parseLinkedDeviceSessionClaimRequestV1>;
  readonly approval: LinkedDeviceApprovalV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly sourceWalletKeyId: WalletKeyId;
  readonly sourceMaterialActivation: MpcMaterialActivationRef;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly packageSetDigestB64u: DigestB64u;
  /** Approval-time authority digest pinned into the transcript. */
  readonly sourceAuthorityDigestB64u: DigestB64u;
};

export function buildR103DeviceLinkFixture(
  input: {
    readonly linkSessionId?: string;
    readonly enrollmentId?: string;
    readonly deviceId?: string;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly issuedAtMs?: number;
    readonly expiresAtMs?: number;
  } = {},
): R103DeviceLinkFixture {
  const targetFactor = input.targetFactor ?? ({ kind: 'passkey_prf' } as const);
  const linkSessionId = required(
    parseLinkDeviceSessionId(input.linkSessionId ?? 'link-session:r103'),
  );
  const walletId = required(parseWalletId('wallet:r103'));
  const enrollmentId = required(
    parseLinkedDeviceEnrollmentId(input.enrollmentId ?? 'enrollment:r103'),
  );
  const deviceId = required(parseLinkedDeviceId(input.deviceId ?? 'device:r103'));
  const walletKeyId = required(parseWalletKeyId('wallet-key:r103'));
  const payload = parseQrLinkedDeviceSessionPayloadV5({
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId,
    linkPublicKeyB64u: PUBLIC_KEY_B64U,
    devicePublicKeyB64u: PUBLIC_KEY_B64U,
    requestedPermission: buildSigningOnlyDelegatedWalletAuthorityV1(),
    targetFactor,
    issuedAtMs: input.issuedAtMs ?? 1_000,
    expiresAtMs: input.expiresAtMs ?? 10_000,
  });
  const sourceMaterialActivation = buildMpcMaterialActivationRef({
    activationId: required(parseMpcMaterialActivationId('activation:r103')),
    capability: required(parseCapabilityInstanceRef('capability:r103')),
    materialOwner: required(parseMpcMaterialOwnerRef('owner:r103')),
    keyBinding: required(parseMpcKeyBindingRef('key-binding:r103')),
    lifecycleBinding: required(parseMpcLifecycleBindingRef('lifecycle:r103')),
    signingWorker: required(parseMpcSigningWorkerRef('worker:r103')),
  });
  const sourceWalletAuthMethodId = required(parseWalletAuthMethodId('passkey:wallet:r103'));
  const approvedTargetFactor: LinkedDeviceApprovedTargetFactorV1 =
    targetFactor.kind === 'passkey_prf'
      ? { kind: 'passkey_prf' }
      : {
          kind: 'email_otp',
          baseWalletAuthMethodId: required(parseWalletAuthMethodId('email-otp:wallet:r103')),
        };
  const sourceSignerManifest = buildExactAdministeredSignerManifestV1([
    {
      kind: 'exact_administered_ed25519_signer_v1',
      keyFamily: 'ed25519',
      walletId,
      walletKeyId,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(PUBLIC_KEY_B64U),
    },
  ]);
  const approval = buildLinkedDeviceApprovalV1({
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    linkPublicKeyB64u: payload.linkPublicKeyB64u,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    permission: payload.requestedPermission,
    targetFactor: approvedTargetFactor,
    ownerAuthorization: buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
      walletSessionId: required(parseWalletSessionId('ws:r103')),
      authorizationId: required(parseWalletSessionAuthorizationId('wsa:r103')),
    }),
    approvedAtMs: 2_000,
    expiresAtMs: 9_000,
  });
  const claimRequest = parseLinkedDeviceSessionClaimRequestV1({
    kind: 'linked_device_session_claim_request_v1',
    payload,
  });
  return {
    payload,
    claimRequest,
    approval,
    sourceSignerManifest,
    sourceWalletKeyId: walletKeyId,
    sourceMaterialActivation,
    sourceWalletAuthMethodId,
    packageSetDigestB64u: FIXTURE_DIGEST,
    sourceAuthorityDigestB64u: FIXTURE_DIGEST,
  };
}

export function buildR103OwnerApprovalContextV1(
  approval: LinkedDeviceApprovalV1,
  overrides: { readonly keyManifestDigestB64u?: DigestB64u } = {},
) {
  return {
    walletId: approval.walletId,
    walletSessionId: required(parseWalletSessionId('ws:r103')),
    authorizationId: required(parseWalletSessionAuthorizationId('wsa:r103')),
    expiresAtMs: approval.expiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    curve: 'ed25519' as const,
    keyManifestDigestB64u:
      overrides.keyManifestDigestB64u ??
      parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE'),
  };
}

export function buildR103EcdsaSourceContributionPreparationV1(
  fixture: R103DeviceLinkFixture,
): LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1 {
  const compressedPublicKey = base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(1)]));
  const recipientPublicKey = base64UrlEncode(new Uint8Array(32).fill(2));
  const secondRecipientPublicKey = base64UrlEncode(new Uint8Array(32).fill(3));

  return parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1([
    {
      linkSessionId: fixture.approval.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      sourceAuthorityId: 'authority:r103',
      source: {
        activation: buildR103EcdsaActivation('source'),
        clientPublicKey33B64u: compressedPublicKey,
        relayerPublicKey33B64u: compressedPublicKey,
        thresholdPublicKey33B64u: compressedPublicKey,
        thresholdEthereumAddress20B64u: base64UrlEncode(new Uint8Array(20).fill(5)),
      },
      target: {
        activation: buildR103EcdsaActivation('target'),
        targetDeviceId: fixture.approval.deviceId,
        targetFactorVerificationDigestB64u: fixture.packageSetDigestB64u,
        clientRecipientPublicKeyB64u: recipientPublicKey,
        signingWorkerRecipientPublicKeyB64u: secondRecipientPublicKey,
      },
    },
  ]);
}

export function buildR103EcdsaSourceContributionV1(
  fixture: R103DeviceLinkFixture,
): LinkedDeviceOrdinaryMaterialSourceContributionV1 {
  const preparation = buildR103EcdsaSourceContributionPreparationV1(fixture)[0];
  if (!preparation || 'kind' in preparation) {
    throw new Error('R103 ECDSA preparation is missing');
  }
  const walletKeyId = fixture.sourceWalletKeyId;
  const sourceSigner = {
    activation: preparation.source.activation,
    clientPublicKey33B64u: preparation.source.clientPublicKey33B64u,
    relayerPublicKey33B64u: preparation.source.relayerPublicKey33B64u,
    thresholdPublicKey33B64u: preparation.source.thresholdPublicKey33B64u,
    thresholdEthereumAddress20B64u: preparation.source.thresholdEthereumAddress20B64u,
  };
  const sourceNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: sourceSigner.activation.materialOwner,
      ecdsa_threshold_key_id: 'ecdsa-threshold-key:r103',
      signing_root_id: 'signing-root:r103',
      signing_root_version: 'signing-root-version:r103',
      context: {
        application_binding_digest_b64u: fixture.packageSetDigestB64u,
      },
      public_identity: {
        context_binding_b64u: base64UrlEncode(new Uint8Array(32).fill(19)),
        derivation_client_share_public_key33_b64u: sourceSigner.clientPublicKey33B64u,
        server_public_key33_b64u: sourceSigner.relayerPublicKey33B64u,
        threshold_public_key33_b64u: sourceSigner.thresholdPublicKey33B64u,
        ethereum_address20_b64u: sourceSigner.thresholdEthereumAddress20B64u,
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(sourceSigner.activation),
      signing_worker: {
        server_id: sourceSigner.activation.signingWorker,
        key_epoch: 'signing-worker-key-epoch:r103',
        recipient_encryption_key: `x25519:${'ab'.repeat(32)}`,
      },
      activation_epoch: 'root-share-epoch:r103',
    },
  });
  const binding = {
    linkSessionId: preparation.linkSessionId,
    enrollmentId: preparation.enrollmentId,
    sourceAuthorityId: preparation.sourceAuthorityId,
    source: sourceSigner,
    target: preparation.target,
    targetClientPublicKey33B64u: base64UrlEncode(
      new Uint8Array([2, ...new Uint8Array(32).fill(7)]),
    ),
  };
  return parseLinkedDeviceOrdinaryMaterialSourceContributionV1({
    kind: 'linked_device_ecdsa_source_contribution_v1',
    keyFamily: 'ecdsa_secp256k1',
    linkSessionId: preparation.linkSessionId,
    enrollmentId: preparation.enrollmentId,
    sourceAuthorityId: preparation.sourceAuthorityId,
    walletKeyId,
    targetDeviceId: preparation.target.targetDeviceId,
    targetFactorVerificationDigestB64u: preparation.target.targetFactorVerificationDigestB64u,
    sourceSigner,
    sourceDerivation: {
      applicationBindingDigestB64u: fixture.packageSetDigestB64u,
      clientShareRetryCounter: 0,
      ecdsaThresholdKeyId: 'ecdsa-threshold-key:r103',
      sourceNormalSigning,
    },
    target: preparation.target,
    package: {
      binding,
      encryptedDelta: buildR103EcdsaEnvelope(
        preparation.target.signingWorkerRecipientPublicKeyB64u,
        11,
      ),
      encryptedTargetClientShare: buildR103EcdsaEnvelope(
        preparation.target.clientRecipientPublicKeyB64u,
        13,
      ),
    },
  });
}

function buildR103EcdsaEnvelope(recipientPublicKeyB64u: string, seed: number) {
  return {
    kind: LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
    recipientPublicKeyB64u,
    bindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(17)),
    encappedKeyB64u: base64UrlEncode(new Uint8Array(32).fill(seed)),
    ciphertextB64u: base64UrlEncode(new Uint8Array(32).fill(seed + 1)),
  };
}
