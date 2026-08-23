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
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { mpcMaterialActivationRefsEqual, parseWalletKeyId } from '@shared/utils/domainIds';
import type { ExactAdministeredSignerV1 } from '@shared/device-linking/delegatedActivationPlan';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { AuthorizationService } from '../../../../authorization/service';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../../../core/WalletStore';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import type {
  VerifiedLinkSourceReadV1,
  VerifiedLinkSourceReaderV1,
} from './d1LinkedDeviceVerifiedLinkBuilder';

export function createD1LinkedDeviceVerifiedLinkSourceReaderV1(input: {
  readonly authorizationService: Pick<
    AuthorizationService,
    'readWalletSessionAuthorizationV2ByIdentity'
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
      const issued = await input.authorizationService.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: input.tenantId,
        walletId: request.walletId,
        walletSessionId: walletSessionId.value,
        authorizationId: authorizationId.value,
        nowMs: request.requestedAtMs,
      });
      if (!issued) throw new Error('source Wallet Session V2 is unavailable');
      const session = issued.session;
      if (
        session.walletId !== request.walletId ||
        session.walletSessionId !== walletSessionId.value ||
        session.authorizationId !== authorizationId.value
      ) {
        throw new Error('source Wallet Session V2 identity changed');
      }
      if (session.expiresAtMs <= request.requestedAtMs) {
        throw new Error('source Wallet Session V2 is expired');
      }
      const authority = await input.authorityStore.readById(session.authorityId);
      if (!authority || authority.state !== 'active') {
        throw new Error('source Wallet Authority is not active');
      }
      const authMethod = await input.authMethodStore.readByIdV2({
        walletAuthMethodId: session.walletAuthMethodId,
      });
      if (!authMethod || authMethod.status !== 'active') {
        throw new Error('source Wallet Auth Method is not active');
      }
      if (
        authMethod.walletId !== session.walletId ||
        authMethod.walletAuthorityId !== session.authorityId ||
        authority.authorityDigestB64u !== session.authorityDigestB64u ||
        authority.revocationEpoch !== session.authorityRevocationEpoch
      ) {
        throw new Error('source Wallet Auth Method authority provenance is invalid');
      }
      const [ed25519Signers, ecdsaSigners] = await Promise.all([
        input.walletStore.listEd25519SignersForWallet({ walletId: session.walletId }),
        input.walletStore.listEcdsaSignersForWallet({ walletId: session.walletId }),
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
        principalId: session.principalId,
        expiresAtMs: session.expiresAtMs,
        authorityDigestB64u: session.authorityDigestB64u,
        verifiedRevocationEpoch: session.authorityRevocationEpoch,
        verifiedAtMs: request.requestedAtMs,
      } satisfies VerifiedLinkSourceReadV1;
    },
  };
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
