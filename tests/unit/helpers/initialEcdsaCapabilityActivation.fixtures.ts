import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify } from '@shared/utils/digests';
import { parseCanonicalEcdsaServerActivationRequest } from '@shared/utils/ecdsaCapabilityActivation';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { RouterAbEcdsaVerifiedClientActivationFactsV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { InitialEcdsaCapabilityActivationPlanInput } from '@/core/signingEngine/session/material/initialEcdsaCapabilityActivation';
import { toParticipantId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

const REQUEST_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(21));
const BINDING_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(22));
const CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...new Array<number>(32).fill(23)]),
);

export type InitialEcdsaCapabilityActivationFixture = {
  readonly input: InitialEcdsaCapabilityActivationPlanInput;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly forbiddenAliases: readonly [string, string, string];
};

export async function initialEcdsaCapabilityActivationFixture(options: {
  readonly canonicalRequestCeremonyId?: string;
} = {}): Promise<InitialEcdsaCapabilityActivationFixture> {
  const walletId = walletIdFromString('initial-ecdsa-activation-wallet');
  const authority = await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId,
      rpId: 'wallet.example.test',
      credentialIdB64u: 'new-passkey-credential',
    }),
  });
  const journalId = parseCorrelationId('initial-ecdsa-registration-ceremony');
  const clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1 = {
    registrationRequestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(24)),
    proofTranscriptDigestB64u: base64UrlEncode(new Uint8Array(32).fill(25)),
    contextBinding32B64u: BINDING_DIGEST_B64U,
    derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
    clientShareRetryCounter: 0,
    participantId: 1,
  };
  return {
    input: {
      authority,
      targetMemberships: [
        {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 1,
          networkSlug: 'ethereum',
        },
      ],
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('initial-ecdsa-threshold-key'),
      signingRootId: parseSdkEcdsaDerivationSigningRootId('initial-ecdsa-signing-root'),
      signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion('v1'),
      clientVerifyingPublicKey33B64u:
        parseEcdsaClientVerifyingPublicKey33B64u(CLIENT_PUBLIC_KEY_B64U),
      participantIds: [toParticipantId(1), toParticipantId(2)],
      relayerKeyId: parseEcdsaRelayerKeyId('initial-ecdsa-relayer'),
      bindingDigest: parseEcdsaRoleLocalBindingDigest(BINDING_DIGEST_B64U),
      journalId,
      requestDigest: parseDigestB64u(REQUEST_DIGEST_B64U),
      canonicalRequest: parseCanonicalEcdsaServerActivationRequest(
        alphabetizeStringify({
          registrationCeremonyId: options.canonicalRequestCeremonyId ?? journalId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activation_v1',
            activationCorrelationId: journalId,
            publicFacts: clientActivation,
            expectedActivationRequestDigest: {
              bytes: new Array<number>(32).fill(21),
            },
          },
        }),
      ),
      createdAt: parseIsoTimestamp('2026-07-27T00:00:00.000Z'),
    },
    clientActivation,
    forbiddenAliases: [
      journalId,
      'initial-ecdsa-threshold-session',
      'initial-ecdsa-worker-material-handle',
    ],
  };
}
