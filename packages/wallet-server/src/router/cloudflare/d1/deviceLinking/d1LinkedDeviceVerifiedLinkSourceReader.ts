import {
  buildExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import type { AuthorizationService } from '../../../../authorization/service';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
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
        authMethod.walletAuthorityId !== session.authorityId
      ) {
        throw new Error('source Wallet Auth Method authority provenance is invalid');
      }
      return {
        authority,
        authMethod,
        signerManifest: signerManifestFromAuthority(authority),
        authorityDigestB64u: session.authorityDigestB64u,
        verifiedRevocationEpoch: session.authorityRevocationEpoch,
        verifiedAtMs: request.requestedAtMs,
      } satisfies VerifiedLinkSourceReadV1;
    },
  };
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
