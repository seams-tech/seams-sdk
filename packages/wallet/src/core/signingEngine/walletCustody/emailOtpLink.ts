/**
 * Refactor 109C: sealing the wallet's existing custody seed under a newly
 * verified Email OTP factor.
 *
 * The mirror of `passkeyLink`, and deliberately the same shape: open the source
 * envelope with the factor secret the caller already collected, reseal the same
 * seed under the new factor, commit the ciphertext with the auth method in one
 * server call. No ceremony runs — nothing is derived and no key manifest is
 * verified, because the seed is the wallet's own and the envelope it came from
 * already proved that.
 *
 * The Email factor secret is generated here and never returned. It is sealed to
 * the server's enrollment key so a future OTP verification can release it back,
 * and it is used once, in the worker, to seal the new envelope.
 */
import {
  buildEmailOtpEnvelopeFactor,
  buildMethodBoundEnvelopeOwnership,
  buildPasskeyCustodyEnvelopeRecord,
  custodyEnvelopeBindingJsonV1,
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parsePasskeyCustodyEnvelopeRecord,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '@shared/passkey-custody';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parsePasskeyEnvelopeId, type WalletAuthMethodId } from '@shared/utils/domainIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  finalizeWalletAddAuthMethod,
  startWalletAddAuthMethod,
  type AddAuthMethodAuth,
  type WalletAddAuthMethodAuthority,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import type { WalletCustodyCeremonyTransportPort } from './ceremonyStepRunner';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function requireResealedEnvelope(value: unknown): {
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  readonly aadHashB64u: DigestB64u;
  readonly ciphertextDigestB64u: DigestB64u;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Email OTP custody worker returned no resealed envelope');
  }
  const record = value as Record<string, unknown>;
  return {
    nonceB64u: parseEnvelopeNonceB64u(record.nonceB64u, 'resealed envelope nonceB64u'),
    sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      record.sealedCustodySecretB64u,
      'resealed envelope sealedCustodySecretB64u',
    ),
    aadHashB64u: parseDigestField(record.aadHashB64u, 'resealed envelope aadHashB64u'),
    ciphertextDigestB64u: parseDigestField(
      record.ciphertextDigestB64u,
      'resealed envelope ciphertextDigestB64u',
    ),
  };
}

/** Complete add-email-code custody linking from the browser boundary. */
export async function linkWalletEmailOtpCustody(input: {
  readonly context: RegistrationWebContext;
  readonly relayerUrl: string;
  readonly walletId: Parameters<typeof startWalletAddAuthMethod>[0]['walletId'];
  readonly addAuthMethodIntentGrant: Parameters<
    typeof startWalletAddAuthMethod
  >[0]['addAuthMethodIntentGrant'];
  readonly addAuthMethodIntentDigestB64u: string;
  readonly intent: Parameters<typeof startWalletAddAuthMethod>[0]['intent'];
  readonly auth: AddAuthMethodAuth;
  readonly authority: Extract<WalletAddAuthMethodAuthority, { kind: 'email_otp' }>;
  readonly existingFactorSecret: Uint8Array;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly providerSubject: string;
  readonly worker: WalletCustodyCeremonyTransportPort;
  readonly nowMs?: () => number;
}): Promise<{
  readonly finalized: Awaited<ReturnType<typeof finalizeWalletAddAuthMethod>>;
  readonly enrollmentId: string;
}> {
  const started = await startWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodIntentGrant: input.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: input.addAuthMethodIntentDigestB64u,
    intent: input.intent,
    auth: input.auth,
    authority: input.authority,
  });
  if (!started.custodyEnvelope) {
    throw new Error('Email OTP add-auth-method start omitted the source custody envelope');
  }
  const sourceEnvelope = started.custodyEnvelope;

  /* Generated after the start succeeds, so a refused ceremony costs no seal.
     This is the Email factor secret: sealed to the enrollment key so a verified
     OTP can release it back, and held here only long enough to seal one
     envelope. */
  const clientSecret32 = crypto.getRandomValues(new Uint8Array(32));
  /* Copied before the preparer runs: it seals and then zeroes what it is given,
     and this same secret has to seal the envelope afterwards. */
  const replacementFactorSecret = clientSecret32.slice();
  let enrollment: Awaited<
    ReturnType<
      RegistrationWebContext['signingEngine']['prepareEmailOtpRegistrationEnrollmentMaterialInternal']
    >
  >;
  try {
    enrollment =
      await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
        relayUrl: input.relayerUrl,
        walletId: toWalletId(String(input.walletId)),
        userId: input.providerSubject,
        clientSecret32,
      });
  } catch (error: unknown) {
    replacementFactorSecret.fill(0);
    throw error;
  } finally {
    clientSecret32.fill(0);
  }

  const envelopeIdResult = parsePasskeyEnvelopeId(
    secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
  );
  if (!envelopeIdResult.ok) throw new Error(envelopeIdResult.error.message);
  const factor = buildEmailOtpEnvelopeFactor({
    enrollmentId: enrollment.enrollmentId,
    enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
  });
  const ownership = buildMethodBoundEnvelopeOwnership(input.walletAuthMethodId);
  const envelopeRevision = parseEnvelopeRevision(1);
  const replacementBindingJson = custodyEnvelopeBindingJsonV1({
    walletId: sourceEnvelope.walletId,
    envelopeId: envelopeIdResult.value,
    factor,
    envelopeRevision,
    binding: sourceEnvelope.binding,
    ownership,
  });

  /* The reseal itself is factor-agnostic — it opens with one secret and seals
     with another — so this is the same worker operation the Passkey branch
     uses. Both buffers are transferred and zeroed by the worker. */
  const existingFactorSecret = input.existingFactorSecret.slice();
  let resealed: ReturnType<typeof requireResealedEnvelope>;
  try {
    resealed = requireResealedEnvelope(
      await input.worker.requestOperation({
        kind: 'walletCustodyCeremony',
        request: {
          type: 'linkWalletCustodyPasskey',
          payload: {
            existingEnvelope: sourceEnvelope,
            existingFactorSecret: existingFactorSecret.buffer,
            replacementEnvelopeBindingJson: replacementBindingJson,
            replacementFactorSecret: replacementFactorSecret.buffer,
          },
          transfer: [existingFactorSecret.buffer, replacementFactorSecret.buffer],
        },
      }),
    );
  } finally {
    /* Both buffers were transferred to the worker, which detaches them here.
       Zeroing a detached buffer throws; the worker owns and wipes the bytes
       once the transfer succeeds, so the guard is the whole cleanup. */
    if (existingFactorSecret.byteLength > 0) existingFactorSecret.fill(0);
    if (replacementFactorSecret.byteLength > 0) replacementFactorSecret.fill(0);
  }

  const nowMs = (input.nowMs ?? Date.now)();
  const custodyEnvelope = parsePasskeyCustodyEnvelopeRecord(
    buildPasskeyCustodyEnvelopeRecord({
      envelopeId: envelopeIdResult.value,
      walletId: sourceEnvelope.walletId,
      ownership,
      binding: sourceEnvelope.binding,
      factor,
      envelopeRevision,
      nonceB64u: resealed.nonceB64u,
      sealedCustodySecretB64u: resealed.sealedCustodySecretB64u,
      ciphertextDigestB64u: resealed.ciphertextDigestB64u,
      aadHashB64u: resealed.aadHashB64u,
      lifecycle: { state: 'active', activatedAtMs: nowMs },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    }),
  );
  const finalized = await finalizeWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    custodyEnvelope,
    /* This branch enrols. A wallet that already has a shared Email enrollment
       — one that linked a device, or holds an Email method on another
       authority — binds to it instead, and that case does not come through
       here: it needs the existing enrollment's factor secret, which only an
       OTP factor release can hand back. */
    emailOtpTarget: { kind: 'new_enrollment', enrollment: enrollment.emailOtpEnrollment },
  });
  return { finalized, enrollmentId: enrollment.enrollmentId };
}
