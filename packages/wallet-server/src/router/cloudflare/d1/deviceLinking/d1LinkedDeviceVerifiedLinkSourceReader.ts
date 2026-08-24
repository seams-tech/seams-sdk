import {
  buildExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import type { LinkedDeviceOwnerSourceLaneV1 } from '@shared/device-linking/contracts';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { mpcMaterialActivationRefsEqual, parseWalletKeyId } from '@shared/utils/domainIds';
import type { ExactAdministeredSignerV1 } from '@shared/device-linking/delegatedActivationPlan';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { AuthorizationService } from '../../../../authorization/service';
import type {
  OpaqueWalletSessionCurve,
  ResolvedOpaqueWalletSessionToken,
} from '../../../../authorization/service';
import type { WalletSessionAuthorizationV2 } from '../../../../authorization/domain';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../../../core/WalletStore';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import type { CloudflareD1AuthorizationStore } from '../authorization/d1AuthorizationStore';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  VerifiedLinkSourceReadV1,
  VerifiedLinkSourceReaderV1,
} from './d1LinkedDeviceVerifiedLinkBuilder';

export function createD1LinkedDeviceVerifiedLinkSourceReaderV1(input: {
  readonly authorizationService: Pick<
    AuthorizationService,
    'readWalletSessionAuthorizationV2ByIdentity'
  >;
  readonly ordinaryWalletSessions: Pick<
    CloudflareD1AuthorizationStore,
    'readOpaqueWalletSessionTokenByIdentity'
  >;
  readonly authorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'>;
  readonly walletStore: Pick<
    D1WalletStore,
    'listEd25519SignersForWallet' | 'listEcdsaSignersForWallet'
  >;
  readonly tenantId: TenantId;
}): VerifiedLinkSourceReaderV1 {
  return {
    readVerifiedSourceV1: async (request) => {
      const walletSessionId = parseWalletSessionId(request.walletSessionId);
      const authorizationId = parseWalletSessionAuthorizationId(request.authorizationId);
      if (!walletSessionId.ok || !authorizationId.ok) {
        throw new Error('source Wallet Session identity is invalid');
      }
      const sourceSession = await resolveSourceWalletSessionV1({
        authorizationService: input.authorizationService,
        ordinaryWalletSessions: input.ordinaryWalletSessions,
        tenantId: input.tenantId,
        walletId: request.walletId,
        walletSessionId: walletSessionId.value,
        authorizationId: authorizationId.value,
        keyFamily: request.keyFamily,
        nowMs: request.requestedAtMs,
      });
      const walletAuthMethodId = sourceWalletAuthMethodIdV1(sourceSession);
      const authMethod = await input.authMethodStore.readByIdV2({ walletAuthMethodId });
      if (!authMethod || authMethod.status !== 'active') {
        throw new Error('source Wallet Auth Method is not active');
      }
      const authorityId =
        sourceSession.kind === 'wallet_session_v2'
          ? sourceSession.session.authorityId
          : authMethod.walletAuthorityId;
      const authority = await input.authorityStore.readById(authorityId);
      if (!authority || authority.state !== 'active') {
        throw new Error('source Wallet Authority is not active');
      }
      if (authMethod.walletId !== request.walletId || authMethod.walletAuthorityId !== authorityId) {
        throw new Error('source Wallet Auth Method authority provenance is invalid');
      }
      assertSourceSessionAuthorityV1(sourceSession, authority);
      const [ed25519Signers, ecdsaSigners] = await Promise.all([
        input.walletStore.listEd25519SignersForWallet({ walletId: request.walletId }),
        input.walletStore.listEcdsaSignersForWallet({ walletId: request.walletId }),
      ]);
      const signer = sourceSignerForFamilyV1({
        authority,
        keyFamily: request.keyFamily,
        signers: request.keyFamily === 'ed25519' ? ed25519Signers : ecdsaSigners,
      });
      return {
        authority,
        authMethod,
        signerManifest: signerManifestFromAuthority(authority),
        keyManifestDigestB64u: parseDigestB64u(signer.custodyKeyManifestDigestB64u),
        principalId: sourceSessionPrincipalIdV1(sourceSession),
        expiresAtMs: sourceSessionExpiresAtMsV1(sourceSession),
        authorityDigestB64u: authority.authorityDigestB64u,
        verifiedRevocationEpoch: authority.revocationEpoch,
        verifiedAtMs: request.requestedAtMs,
      } satisfies VerifiedLinkSourceReadV1;
    },
  };
}

type SourceWalletSessionV1 =
  | {
      readonly kind: 'wallet_session_v2';
      readonly session: WalletSessionAuthorizationV2;
    }
  | {
      readonly kind: 'ordinary_wallet_session';
      readonly session: ResolvedOpaqueWalletSessionToken;
    };

async function resolveSourceWalletSessionV1(input: {
  readonly authorizationService: Pick<
    AuthorizationService,
    'readWalletSessionAuthorizationV2ByIdentity'
  >;
  readonly ordinaryWalletSessions: Pick<
    CloudflareD1AuthorizationStore,
    'readOpaqueWalletSessionTokenByIdentity'
  >;
  readonly tenantId: TenantId;
  readonly walletId: Parameters<VerifiedLinkSourceReaderV1['readVerifiedSourceV1']>[0]['walletId'];
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly keyFamily: LinkedDeviceOwnerSourceLaneV1['keyFamily'];
  readonly nowMs: number;
}): Promise<SourceWalletSessionV1> {
  const issued = await input.authorizationService.readWalletSessionAuthorizationV2ByIdentity({
    tenantId: input.tenantId,
    walletId: input.walletId,
    walletSessionId: input.walletSessionId,
    authorizationId: input.authorizationId,
    nowMs: input.nowMs,
  });
  if (issued) {
    const session = issued.session;
    if (
      session.walletId !== input.walletId ||
      session.walletSessionId !== input.walletSessionId ||
      session.authorizationId !== input.authorizationId ||
      session.expiresAtMs <= input.nowMs
    ) {
      throw new Error('source Wallet Session V2 identity changed or expired');
    }
    return { kind: 'wallet_session_v2', session };
  }

  const curve: OpaqueWalletSessionCurve =
    input.keyFamily === 'ed25519' ? 'ed25519' : 'ecdsa';
  const ordinary = await input.ordinaryWalletSessions.readOpaqueWalletSessionTokenByIdentity({
    tenantId: input.tenantId,
    walletSessionId: input.walletSessionId,
    curve,
    nowMs: input.nowMs,
  });
  if (!ordinary) throw new Error('source Wallet Session is unavailable');
  const binding = ordinary.binding;
  if (
    ordinary.curve !== curve ||
    ordinary.authorization.walletId !== input.walletId ||
    ordinary.authorization.walletSessionId !== input.walletSessionId ||
    ordinary.authorization.authorizationId !== input.authorizationId ||
    ordinary.authorization.expiresAtMs <= input.nowMs ||
    binding.walletId !== input.walletId ||
    binding.walletSessionId !== input.walletSessionId ||
    binding.authorizationId !== input.authorizationId
  ) {
    throw new Error('source ordinary Wallet Session identity changed or expired');
  }
  const authorityRef =
    binding.curve === 'ed25519'
      ? await walletAuthAuthorityRef({ authority: binding.authority })
      : binding.walletAuthAuthorityRef;
  if (String(authorityRef.authorityDigest) !== String(ordinary.authorization.authorityDigest)) {
    throw new Error('source ordinary Wallet Session authority changed');
  }
  if (
    ordinary.authorization.walletAuthMethodId !== null &&
    ordinary.authorization.walletAuthMethodId !== authorityRef.walletAuthMethodId
  ) {
    throw new Error('source ordinary Wallet Session auth method changed');
  }
  return { kind: 'ordinary_wallet_session', session: ordinary };
}

function sourceWalletAuthMethodIdV1(source: SourceWalletSessionV1) {
  switch (source.kind) {
    case 'wallet_session_v2':
      return source.session.walletAuthMethodId;
    case 'ordinary_wallet_session':
      return source.session.binding.curve === 'ed25519'
        ? source.session.binding.authority.bindingId
        : source.session.binding.walletAuthAuthorityRef.walletAuthMethodId;
  }
}

function sourceSessionPrincipalIdV1(source: SourceWalletSessionV1) {
  return source.kind === 'wallet_session_v2'
    ? source.session.principalId
    : source.session.authorization.principalId;
}

function sourceSessionExpiresAtMsV1(source: SourceWalletSessionV1): number {
  return source.kind === 'wallet_session_v2'
    ? source.session.expiresAtMs
    : source.session.authorization.expiresAtMs;
}

function assertSourceSessionAuthorityV1(
  source: SourceWalletSessionV1,
  authority: ActiveWalletAuthorityV1,
): void {
  if (source.kind === 'ordinary_wallet_session') return;
  if (
    source.session.authorityId !== authority.authorityId ||
    source.session.authorityDigestB64u !== authority.authorityDigestB64u ||
    source.session.authorityRevocationEpoch !== authority.revocationEpoch
  ) {
    throw new Error('source Wallet Session V2 authority provenance is invalid');
  }
}

function sourceSignerForFamilyV1(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly keyFamily: LinkedDeviceOwnerSourceLaneV1['keyFamily'];
  readonly signers: readonly (WalletEd25519SignerRecord | WalletEcdsaSignerRecord)[];
}): WalletEd25519SignerRecord | WalletEcdsaSignerRecord {
  const activation =
    input.keyFamily === 'ed25519'
      ? input.authority.signerActivations.ed25519
      : input.authority.signerActivations.ecdsa;
  if (!activation) throw new Error(`source ${input.keyFamily} activation is missing`);
  const matches = input.signers.filter((signer) => {
    if (signer.walletId !== input.authority.walletId) return false;
    if (
      (input.keyFamily === 'ed25519' && signer.version !== 'wallet_signer_ed25519_v1') ||
      (input.keyFamily === 'ecdsa_secp256k1' && signer.version !== 'wallet_signer_ecdsa_v1')
    ) {
      return false;
    }
    try {
      const wire =
        signer.version === 'wallet_signer_ed25519_v1'
          ? signer.activeYaoCapability.activationResult.public_receipt.material_activation
          : signer.walletKey.publicCapability.material_activation;
      if (
        !mpcMaterialActivationRefsEqual(
          routerAbMpcMaterialActivationRefFromWire(wire),
          activation.materialActivation,
        )
      ) {
        return false;
      }
      return sourceSignerIdentityMatchesV1(signer, activation.signer);
    } catch {
      return false;
    }
  });
  if (matches.length === 0) {
    throw new Error(`source ${input.keyFamily} signer identity is unavailable or ambiguous`);
  }
  const signer = matches[0];
  if (!signer) throw new Error(`source ${input.keyFamily} signer identity is unavailable`);
  // ECDSA stores one row per chain target; the authority identity is wallet-wide.
  const keyManifestDigestB64u = parseDigestB64u(signer.custodyKeyManifestDigestB64u);
  for (const duplicate of matches.slice(1)) {
    if (parseDigestB64u(duplicate.custodyKeyManifestDigestB64u) !== keyManifestDigestB64u) {
      throw new Error(`source ${input.keyFamily} signer identity is unavailable or ambiguous`);
    }
  }
  return signer;
}

function sourceSignerIdentityMatchesV1(
  signer: WalletEd25519SignerRecord | WalletEcdsaSignerRecord,
  expected: ExactAdministeredSignerV1,
): boolean {
  if (signer.version === 'wallet_signer_ed25519_v1') {
    if (expected.keyFamily !== 'ed25519') return false;
    const walletKeyId = parseWalletKeyId(
      `wallet-key:ed25519:${signer.walletId}:${signer.nearEd25519SigningKeyId}`,
    );
    if (!walletKeyId.ok) return false;
    return (
      expected.walletKeyId === walletKeyId.value &&
      expected.registeredPublicKeyB64u ===
        base64UrlEncode(
          Uint8Array.from(
            signer.activeYaoCapability.activationResult.public_receipt.registered_public_key,
          ),
        )
    );
  }
  if (expected.keyFamily !== 'ecdsa_secp256k1') return false;
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: signer.walletId,
    signingRootId: signer.walletKey.signingRootId,
    signingRootVersion: signer.walletKey.signingRootVersion,
  });
  const walletKeyId = parseWalletKeyId(
    `wallet-key:ecdsa:${signer.walletId}:${evmFamilySigningKeySlotId}`,
  );
  if (!walletKeyId.ok) return false;
  return (
    expected.walletKeyId === walletKeyId.value &&
    expected.thresholdPublicKey33B64u === signer.walletKey.thresholdEcdsaPublicKeyB64u &&
    expected.evmAddress === signer.walletKey.thresholdOwnerAddress
  );
}

function signerManifestFromAuthority(
  authority: ActiveWalletAuthorityV1,
): ExactAdministeredSignerManifestV1 {
  const signers = authority.signerActivations.keyFamilies.map((family) => {
    if (family === 'ed25519') {
      if (!authority.signerActivations.ed25519) {
        throw new Error('source Ed25519 activation is missing');
      }
      return authority.signerActivations.ed25519.signer;
    }
    if (!authority.signerActivations.ecdsa) {
      throw new Error('source ECDSA activation is missing');
    }
    return authority.signerActivations.ecdsa.signer;
  });
  return buildExactAdministeredSignerManifestV1(signers);
}
