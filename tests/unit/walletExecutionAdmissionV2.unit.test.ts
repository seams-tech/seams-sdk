import { expect, test } from '@playwright/test';
import {
  buildAuthorizationGrantRef,
  buildNearEd25519MpcOperationRef,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  buildWalletSessionAuthorizationV2,
  buildActiveWalletSessionQuota,
  buildWalletSessionCapabilitySubjectsV1,
  buildAuthorizedOperation,
  type WalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import type { AuthorizedOperation } from '../../packages/wallet-server/src/authorization/domain';
import {
  authorizeRouterAbEcdsaDerivationNormalSigningRoute,
  authorizeRouterAbEd25519NormalSigningRoute,
  type RouterAbNormalSigningAdmissionAdapter,
} from '../../packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker';
import {
  resolveWalletSessionAuthorizationV2Admission,
  type WalletSessionAuthorizationV2RequestedOperation,
} from '../../packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission';
import {
  validateRouterAbEd25519WalletSessionTokenInputs,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
} from '../../packages/wallet-server/src/router/auth/commonRouterUtils';
import type {
  RouterApiAuthorizedOperationService,
  RouterApiAuthorizationSessionService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
  RouterApiWalletRegistrationService,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEd25519YaoExportAuthorizationIdentityV1 } from '@shared/utils/routerAbEd25519Yao';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

type SignerFamily = 'ed25519' | 'ecdsa_secp256k1' | 'both';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function buildSignerManifest(
  family: SignerFamily,
  walletId: WalletId,
  label: string,
): ReturnType<typeof parseExactAdministeredSignerManifestV1> {
  const ed25519 = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ed25519`,
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(3)),
  };
  const ecdsa = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ecdsa`,
    thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(4)])),
    evmAddress: `0x${'1'.repeat(40)}`,
  };
  switch (family) {
    case 'ed25519':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519'],
        signers: [ed25519],
      });
    case 'ecdsa_secp256k1':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ecdsa_secp256k1'],
        signers: [ecdsa],
      });
    case 'both':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        signers: [ed25519, ecdsa],
      });
  }
}

function buildSignerActivations(family: SignerFamily, walletId: WalletId, label: string) {
  const manifest = buildSignerManifest(family, walletId, label);
  const materialOwner = String(walletId);
  switch (family) {
    case 'ed25519':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
        },
      });
    case 'ecdsa_secp256k1':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
    case 'both':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
  }
}

async function buildAuthority(
  family: SignerFamily,
  label: string,
): Promise<ActiveWalletAuthorityV1> {
  const walletId = required(parseWalletId(`wallet:admission-${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:admission-${label}`));
  const deviceId = required(parseDeviceId(`device:admission-${label}`));
  const signerActivations = buildSignerActivations(family, walletId, label);
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(8))),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    state: 'active',
    activatedAtMs: 100,
  });
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function buildAuthMethod(
  authority: ActiveWalletAuthorityV1,
  label: string,
  status: 'active' | 'revoked',
): WalletAuthMethodRecordV2 {
  const walletAuthMethodId = required(parseWalletAuthMethodId(`passkey:admission-${label}`));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u(`credential:admission-${label}`));
  const common = {
    version: 'wallet_auth_method_v2' as const,
    walletAuthMethodId,
    walletId: authority.walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey' as const,
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
    counter: 0,
    createdAtMs: 200,
    updatedAtMs: 200,
  };
  if (status === 'active') {
    return buildWalletAuthMethodRecordV2({
      ...common,
      status: 'active',
      activatedAtMs: 200,
    });
  }
  return buildWalletAuthMethodRecordV2({
    ...common,
    status: 'revoked',
    activatedAtMs: 200,
    revokedAtMs: 300,
  });
}

function buildSession(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethodId: WalletAuthMethodId;
  readonly label: string;
  readonly capabilitySubjects: WalletSessionAuthorizationV2['capabilitySubjects'];
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly expiresAtMs: number;
}): WalletSessionAuthorizationV2 {
  return buildWalletSessionAuthorizationV2({
    tenantId: required(parseTenantId(`tenant:admission-${input.label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${input.label}`)),
    walletId: input.authority.walletId,
    authorityId: input.authority.authorityId,
    walletAuthMethodId: input.authMethodId,
    authorityDigestB64u: input.authorityDigestB64u,
    authorityRevocationEpoch: input.authorityRevocationEpoch,
    mintId: required(parseReusableWalletSessionMintId(`mint:admission-${input.label}`)),
    authorizationId: required(
      parseWalletSessionAuthorizationId(`authorization:admission-${input.label}`),
    ),
    walletSessionId: required(parseWalletSessionId(`wallet-session:admission-${input.label}`)),
    quotaId: required(parseMpcWalletSigningQuotaId(`quota:admission-${input.label}`)),
    capabilitySubjects: input.capabilitySubjects,
    createdAtMs: 300,
    expiresAtMs: input.expiresAtMs,
  });
}

async function unsupportedAuthorizationSessionOperation(): Promise<never> {
  throw new Error('authorization session operation is outside this test boundary');
}

async function unsupportedAuthorizedOperationOperation(): Promise<never> {
  throw new Error('authorized operation service operation is outside this test boundary');
}

class WalletSessionAuthorizationV2Fixture implements RouterApiAuthorizationSessionService {
  readonly tenantId: WalletSessionAuthorizationV2['tenantId'];

  constructor(private readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext) {
    this.tenantId = context.authorization.session.tenantId;
  }

  readonly readWalletSessionAuthorizationV2ByOperationCredential = async () => {
    return this.context;
  };

  async issueReusableWalletSession(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async issueOpaqueWalletSessionToken(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async resolveOpaqueWalletSessionToken(): Promise<null> {
    return null;
  }

  async readReusableWalletSessionStatus(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async mintHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async redeemHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }
}

class WalletAuthorizedOperationFixture implements RouterApiAuthorizedOperationService {
  readonly tenantId: WalletSessionAuthorizationV2['tenantId'];

  constructor(private readonly operation: AuthorizedOperation) {
    this.tenantId = operation.tenantId;
  }

  async buildVerifiedOwnerProof(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async recordVerifiedWalletOperationFactorEvidenceSet(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async readAuthorizedOperationById(input: {
    readonly authorizedOperationId: AuthorizedOperation['authorizedOperationId'];
  }): Promise<AuthorizedOperation | null> {
    return input.authorizedOperationId === this.operation.authorizedOperationId
      ? this.operation
      : null;
  }

  async readAuthorizedOperation(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async admitAuthorizedOperation(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async completeAuthorizedOperation(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }
}

class Ed25519MaterialActivationFixture {
  readonly runtimePolicyScope: RuntimePolicyScope = {
    orgId: 'org:admission',
    projectId: 'project:admission',
    envId: 'env:admission',
    signingRootVersion: 'root:admission',
  };

  constructor(
    private readonly materialActivation: RouterAbMpcMaterialActivationRefWire,
    private readonly exportIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
  ) {}

  async resolveEd25519MaterialActivation(
    input: Parameters<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>[0],
  ): ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']> {
    return {
      ok: true,
      materialActivation: this.materialActivation,
      nearAccountId: String(input.walletId),
      signerSlot: 1,
      signingWorkerId: this.materialActivation.signing_worker,
      participantIds: [11, 29],
      runtimePolicyScope: this.runtimePolicyScope,
      exportIdentity: this.exportIdentity,
    };
  }
}

class EcdsaMaterialActivationFixture {
  readonly runtimePolicyScope: RuntimePolicyScope = {
    orgId: 'org:admission',
    projectId: 'project:admission',
    envId: 'env:admission',
    signingRootVersion: 'root:admission',
  };
  calls = 0;

  constructor(
    private readonly materialActivation: RouterAbMpcMaterialActivationRefWire,
    private readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1,
  ) {}

  async resolveEcdsaMaterialActivation(
    _input: Parameters<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>[0],
  ): ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']> {
    this.calls += 1;
    return {
      ok: true,
      materialActivation: this.materialActivation,
      keyHandle: 'key-handle:admission',
      relayerKeyId: 'relayer-key:admission',
      participantIds: [11, 29],
      runtimePolicyScope: this.runtimePolicyScope,
      routerAbEcdsaDerivationNormalSigning: this.normalSigning,
    };
  }
}

class AllowingNormalSigningAdmission implements RouterAbNormalSigningAdmissionAdapter {
  calls = 0;

  async evaluatePolicy(): Promise<{ readonly ok: true }> {
    this.calls += 1;
    return { ok: true };
  }
}

function buildAdmissionContext(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: WalletAuthMethodRecordV2;
  readonly session: WalletSessionAuthorizationV2;
}): RouterApiWalletSessionAuthorizationV2AdmissionContext {
  return {
    authorization: {
      session: input.session,
      quota: buildActiveWalletSessionQuota({
        tenantId: input.session.tenantId,
        principalId: input.session.principalId,
        walletSessionId: input.session.walletSessionId,
        quotaId: input.session.quotaId,
        remainingUses: 3,
        expiresAtMs: input.session.expiresAtMs,
      }),
    },
    authority: input.authority,
    authMethod: input.authMethod,
    retiredAtMs: null,
  };
}

function buildOperation(
  authority: ActiveWalletAuthorityV1,
  label: string,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  operationKind:
    | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)[keyof typeof NEAR_ED25519_MPC_OPERATION_KINDS]
    | (typeof EVM_ECDSA_MPC_OPERATION_KINDS)[keyof typeof EVM_ECDSA_MPC_OPERATION_KINDS],
): WalletSessionAuthorizationV2RequestedOperation {
  const identity = {
    tenantId: required(parseTenantId(`tenant:admission-${label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${label}`)),
    walletId: authority.walletId,
  };
  if (keyFamily === 'ed25519') {
    if (
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.exportKey
    ) {
      throw new Error('Ed25519 operation kind is invalid');
    }
    return { ...identity, keyFamily, operationKind };
  }
  if (
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction &&
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.exportKey
  ) {
    throw new Error('ECDSA operation kind is invalid');
  }
  return { ...identity, keyFamily, operationKind };
}

function buildEd25519ExportIdentityFixture(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  walletId: WalletId,
): RouterAbEd25519YaoExportAuthorizationIdentityV1 {
  return {
    scope: {
      lifecycle_id: 'lifecycle:admission-ed25519',
      root_share_epoch: 'epoch:admission-ed25519',
      account_id: String(walletId),
      threshold_session_id: 'threshold-session:admission-ed25519',
      signer_set_id: 'signer-set:admission-ed25519',
      signing_worker_id: materialActivation.signing_worker,
      material_activation: materialActivation,
    },
    application_binding: {
      wallet_id: String(walletId),
      near_ed25519_signing_key_id: 'near-key:admission-ed25519',
      signing_root_id: 'signing-root:admission-ed25519',
      key_creation_signer_slot: 1,
    },
    participant_ids: [11, 29],
    registered_public_key: new Array<number>(32).fill(3),
    state_epoch: 1,
    runtime_policy_binding: new Array<number>(32).fill(4),
  };
}

function buildEcdsaNormalSigningStateFixture(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  walletId: WalletId,
  label: string,
): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(walletId),
      ecdsa_threshold_key_id: `ecdsa-threshold-key:admission-${label}`,
      signing_root_id: `signing-root:admission-${label}`,
      signing_root_version: `signing-root-version:admission-${label}`,
      context: {
        application_binding_digest_b64u: parseDigestB64u(
          base64UrlEncode(new Uint8Array(32).fill(21)),
        ),
      },
      public_identity: {
        context_binding_b64u: base64UrlEncode(new Uint8Array(32).fill(22)),
        derivation_client_share_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...new Uint8Array(32).fill(23)]),
        ),
        server_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...new Uint8Array(32).fill(24)]),
        ),
        threshold_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...new Uint8Array(32).fill(25)]),
        ),
        ethereum_address20_b64u: base64UrlEncode(new Uint8Array(20).fill(26)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: materialActivation,
      signing_worker: {
        server_id: materialActivation.signing_worker,
        key_epoch: `key-epoch:admission-${label}`,
        recipient_encryption_key: `x25519:${'27'.repeat(32)}`,
      },
      activation_epoch: `activation-epoch:admission-${label}`,
    },
  };
}

function buildEcdsaNormalSigningRequestFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly label: string;
}): ReturnType<typeof buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
  const signingDigest32 = new Uint8Array(32).fill(11);
  return buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: input.normalSigning.scope,
    requestId: `request:admission-${input.label}`,
    operationId: `operation:admission-${input.label}`,
    operationDigests: {
      lane_digest_b64u: base64UrlEncode(new Uint8Array(32).fill(10)),
      intent_digest_b64u: base64UrlEncode(signingDigest32),
      display_digest_b64u: base64UrlEncode(new Uint8Array(32).fill(12)),
    },
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: String(input.session.walletSessionId),
    },
    materialActivation: input.materialActivation,
    clientPresignatureId: `presignature:admission-${input.label}`,
    expiresAtMs: Date.now() + 30_000,
    signingDigest32,
    clientRerandomizationCommitment32: new Uint8Array(32).fill(13),
  });
}

async function buildEd25519AuthorizedOperationFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): Promise<AuthorizedOperation> {
  const operation: CapabilityOperationEnvelope = buildCapabilityOperationEnvelope({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    capabilityId: required(parseCapabilityId(input.materialActivation.capability)),
    operationId: required(parseCapabilityOperationId('operation:admission-ed25519')),
    operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
    digests: {
      laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
      intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(11))),
      displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(12))),
    },
  });
  return await buildAuthorizedOperation({
    tenantId: input.session.tenantId,
    authorizedOperationId: required(
      parseAuthorizedOperationId('authorized-operation:admission-ed25519'),
    ),
    auditEventId: required(parseAuthorizationAuditEventId('audit:admission-ed25519')),
    operation,
    authorization: {
      kind: 'authorization_grant',
      authorizationGrantRef: buildAuthorizationGrantRef(input.session.authorizationId),
    },
    quota: {
      kind: 'consume_reusable_wallet_session',
      quotaId: input.session.quotaId,
    },
    claimedAtMs: Date.now(),
  });
}

function authorizedOperationReceiptFixture(
  operation: AuthorizedOperation,
): Record<string, unknown> {
  return {
    kind: 'reusable_wallet_session_authorized_operation_v1',
    authorized_operation_id: String(operation.authorizedOperationId),
    operation_id: String(operation.operation.operationId),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operation.operation.operation.operationKind,
    lane_digest_b64u: String(operation.operation.digests.laneDigest),
    intent_digest_b64u: String(operation.operation.digests.intentDigest),
    display_digest_b64u: String(operation.operation.digests.displayDigest),
    operation_fingerprint_digest: String(operation.operationFingerprintDigest),
  };
}

function ed25519V2FinalizeBodyFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly receipt: Record<string, unknown>;
  readonly expiresAtMs: number;
}): Record<string, unknown> {
  return {
    scope: {
      request_id: 'request:admission-ed25519-finalize',
      account_id: String(input.session.walletId),
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: String(input.session.walletSessionId),
      },
      material_activation: input.materialActivation,
      signing_worker_id: input.materialActivation.signing_worker,
    },
    expires_at_ms: input.expiresAtMs,
    authorized_operation: input.receipt,
    prepare_binding: {
      intent_digest: { bytes: new Array<number>(32).fill(11) },
    },
  };
}

test('admits exact Ed25519 and ECDSA Wallet Session V2 provenance', async () => {
  const authority = await buildAuthority('both', 'valid');
  const authMethod = buildAuthMethod(authority, 'valid', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'valid',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  const edAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ed25519',
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });
  const ecdsaAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ecdsa_secp256k1',
      EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });

  if (!edAdmission.ok || !ecdsaAdmission.ok) {
    throw new Error('valid signer admission was refused');
  }
  expect(edAdmission.keyFamily).toBe('ed25519');
  expect(edAdmission.operationKind).toBe(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
  expect(ecdsaAdmission.keyFamily).toBe('ecdsa_secp256k1');
  expect(ecdsaAdmission.operationKind).toBe(EVM_ECDSA_MPC_OPERATION_KINDS.exportKey);
  expect(edAdmission.walletKeyId).toBe(authority.signerActivations.ed25519.signer.walletKeyId);
  expect(ecdsaAdmission.walletKeyId).toBe(authority.signerActivations.ecdsa.signer.walletKeyId);
});

test('rejects provenance drift, retirement, expiry, subject drift, and missing signer family', async () => {
  const authority = await buildAuthority('both', 'reject');
  const authMethod = buildAuthMethod(authority, 'reject', 'active');
  const subjects = buildWalletSessionCapabilitySubjectsV1(authority);
  const operation = buildOperation(
    authority,
    'reject',
    'ed25519',
    NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  );
  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const epochDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch + 1,
    expiresAtMs: 1_000,
  });
  const expired = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const foreignAuthority = await buildAuthority('both', 'foreign-subject');
  const subjectDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(foreignAuthority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: digestDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_digest_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: epochDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_revocation_epoch_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: expired,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authorization_expired' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: subjectDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'capability_subject_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: buildSession({
        authority,
        authMethodId: authMethod.walletAuthMethodId,
        label: 'reject',
        capabilitySubjects: subjects,
        authorityDigestB64u: authority.authorityDigestB64u,
        authorityRevocationEpoch: authority.revocationEpoch,
        expiresAtMs: 1_000,
      }),
      authority,
      authMethod: buildAuthMethod(authority, 'reject', 'revoked'),
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'auth_method_inactive' });

  const edOnlyAuthority = await buildAuthority('ed25519', 'missing-family');
  const edOnlyMethod = buildAuthMethod(edOnlyAuthority, 'missing-family', 'active');
  const edOnlySession = buildSession({
    authority: edOnlyAuthority,
    authMethodId: edOnlyMethod.walletAuthMethodId,
    label: 'missing-family',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(edOnlyAuthority),
    authorityDigestB64u: edOnlyAuthority.authorityDigestB64u,
    authorityRevocationEpoch: edOnlyAuthority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: edOnlySession,
      authority: edOnlyAuthority,
      authMethod: edOnlyMethod,
      operation: buildOperation(
        edOnlyAuthority,
        'missing-family',
        'ecdsa_secp256k1',
        EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
      ),
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'signer_family_mismatch' });
});

test('ordinary ECDSA admission consumes exact V2 credentials and rejects active-state drift', async () => {
  const authority = await buildAuthority('ecdsa_secp256k1', 'route-bridge');
  const authMethod = buildAuthMethod(authority, 'route-bridge', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const service = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admitted = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: service,
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.context.authorization.session.walletSessionId).toBe(session.walletSessionId);
    expect(admitted.admission.admission.operationKind).toBe(
      EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const rejectedDigest = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: digestDrift }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedDigest).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const rejectedAuthMethod = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({
        authority,
        authMethod: buildAuthMethod(authority, 'route-bridge', 'revoked'),
        session,
      }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedAuthMethod).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const expiredSession = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const rejectedExpiry = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: expiredSession }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedExpiry).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });
});

test('ordinary ECDSA V2 admission rejects exact normal-signing scope drift before downstream admission', async () => {
  const authority = await buildAuthority('ecdsa_secp256k1', 'normal-scope');
  const authMethod = buildAuthMethod(authority, 'normal-scope', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'normal-scope',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    authority.signerActivations.ecdsa.materialActivation,
  );
  const normalSigning = buildEcdsaNormalSigningStateFixture(
    materialActivation,
    authority.walletId,
    'normal-scope',
  );
  const materialResolver = new EcdsaMaterialActivationFixture(
    materialActivation,
    normalSigning,
  );
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admissionAdapter = new AllowingNormalSigningAdmission();
  const body = buildEcdsaNormalSigningRequestFixture({
    session,
    normalSigning,
    materialActivation,
    label: 'normal-scope',
  });

  const admitted = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body,
    rawBody: body,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations: null,
    authorizationSessions,
    admissionAdapter,
    resolveEcdsaMaterialActivation:
      materialResolver.resolveEcdsaMaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });
  expect(admitted).toMatchObject({
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
  });
  expect(admissionAdapter.calls).toBe(1);

  const driftedBody = {
    ...body,
    scope: {
      ...body.scope,
      signing_root_version: `${body.scope.signing_root_version}-drift`,
    },
  };
  const rejected = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body: driftedBody,
    rawBody: driftedBody,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations: null,
    authorizationSessions,
    admissionAdapter,
    resolveEcdsaMaterialActivation:
      materialResolver.resolveEcdsaMaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });
  expect(rejected).toMatchObject({
    ok: false,
    result: {
      status: 403,
      body: {
        ok: false,
        code: 'wallet_session_scope_mismatch',
      },
    },
  });
  expect(materialResolver.calls).toBe(2);
  expect(admissionAdapter.calls).toBe(1);
});

test('ordinary Ed25519 admission consumes exact V2 credentials and rejects active-state drift', async () => {
  const authority = await buildAuthority('ed25519', 'near-route-bridge');
  const authMethod = buildAuthMethod(authority, 'near-route-bridge', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const service = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admitted = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: service,
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.context.authorization.session.walletSessionId).toBe(session.walletSessionId);
    expect(admitted.admission.admission.operationKind).toBe(
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const rejectedDigest = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: digestDrift }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedDigest).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const rejectedAuthMethod = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({
        authority,
        authMethod: buildAuthMethod(authority, 'near-route-bridge', 'revoked'),
        session,
      }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedAuthMethod).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const expiredSession = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const rejectedExpiry = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: expiredSession }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedExpiry).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });
});

test('strict Ed25519 V2 finalize admits the exact receipt operation and rejects drift', async () => {
  const authority = await buildAuthority('ed25519', 'finalize-route');
  const authMethod = buildAuthMethod(authority, 'finalize-route', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'finalize-route',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    authority.signerActivations.ed25519.materialActivation,
  );
  const authorizedOperation = await buildEd25519AuthorizedOperationFixture({
    session,
    materialActivation,
  });
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const authorizedOperations = new WalletAuthorizedOperationFixture(authorizedOperation);
  const materialResolver = new Ed25519MaterialActivationFixture(
    materialActivation,
    buildEd25519ExportIdentityFixture(materialActivation, authority.walletId),
  );
  const admissionAdapter = new AllowingNormalSigningAdmission();
  const expiresAtMs = Date.now() + 30_000;
  const receipt = authorizedOperationReceiptFixture(authorizedOperation);
  const body = ed25519V2FinalizeBodyFixture({
    session,
    materialActivation,
    receipt,
    expiresAtMs,
  });

  const admitted = await authorizeRouterAbEd25519NormalSigningRoute({
    body,
    rawBody: body,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.validated.admission.admission.operationKind).toBe(
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const wrongOperationBody = ed25519V2FinalizeBodyFixture({
    session,
    materialActivation,
    receipt: {
      ...receipt,
      operation_kind: NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction,
    },
    expiresAtMs,
  });
  const rejected = await authorizeRouterAbEd25519NormalSigningRoute({
    body: wrongOperationBody,
    rawBody: wrongOperationBody,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(rejected).toMatchObject({
    ok: false,
    result: {
      status: 400,
      body: { ok: false, code: 'invalid_authorized_operation' },
    },
  });
  expect(admissionAdapter.calls).toBe(1);
});
