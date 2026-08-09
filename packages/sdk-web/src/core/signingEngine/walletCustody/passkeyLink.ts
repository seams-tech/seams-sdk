import {
  buildPasskeyCustodyEnvelopeRecord,
  buildPasskeyEnvelopeFactor,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  parsePasskeyEnvelopeId,
  parseWebAuthnCredentialIdB64u,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  finalizeWalletAddAuthMethod,
  startWalletAddAuthMethod,
  type AddAuthMethodAuth,
  type WalletAddAuthMethodRegistrationOptions,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  serializeRegistrationCredentialWithPRF,
} from '../webauthnAuth/credentials/helpers';
import { getPrfFirstB64uFromCredential } from '../webauthnAuth/credentials/credentialExtensions';
import type { WalletCustodyCeremonyTransportPort } from './ceremonyStepRunner';

type PasskeyRegistrationCredential = ReturnType<typeof serializeRegistrationCredentialWithPRF>;

function requireRegistrationCredential(value: Credential | null): PublicKeyCredential {
  if (!value || !(value instanceof PublicKeyCredential)) {
    throw new Error('Passkey registration did not return a public-key credential');
  }
  return value;
}

function publicKeyCreationOptions(
  options: WalletAddAuthMethodRegistrationOptions,
): PublicKeyCredentialCreationOptions {
  return {
    challenge: base64UrlDecode(options.challengeB64u),
    rp: { id: options.rpId, name: options.rpId },
    user: {
      id: base64UrlDecode(options.user.idB64u),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams.map((parameter) => ({
      type: parameter.type,
      alg: parameter.alg,
    })),
    authenticatorSelection: options.authenticatorSelection,
    timeout: options.timeoutMs,
    attestation: options.attestation,
    excludeCredentials: options.excludeCredentials.map((credential) => ({
      type: credential.type,
      id: base64UrlDecode(credential.id),
    })),
    extensions: {
      prf: {
        eval: {
          first: base64UrlDecode(options.extensions.prf.eval.firstB64u),
          second: base64UrlDecode(options.extensions.prf.eval.secondB64u),
        },
      },
    } as AuthenticationExtensionsClientInputs,
  };
}

function requireResealedEnvelope(value: unknown): {
  readonly nonceB64u: string;
  readonly sealedCustodySecretB64u: string;
  readonly aadHashB64u: string;
  readonly ciphertextDigestB64u: string;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Passkey custody worker returned no resealed envelope');
  }
  const record = value as Record<string, unknown>;
  const nonceB64u = String(record.nonceB64u || '').trim();
  const sealedCustodySecretB64u = String(record.sealedCustodySecretB64u || '').trim();
  const aadHashB64u = String(record.aadHashB64u || '').trim();
  const ciphertextDigestB64u = String(record.ciphertextDigestB64u || '').trim();
  if (!nonceB64u || !sealedCustodySecretB64u || !aadHashB64u || !ciphertextDigestB64u) {
    throw new Error('Passkey custody worker returned incomplete resealed envelope');
  }
  return { nonceB64u, sealedCustodySecretB64u, aadHashB64u, ciphertextDigestB64u };
}

function requireCredentialId(value: string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(value);
  if (!parsed.ok) throw new Error(`Passkey registration credential id is invalid: ${parsed.error.message}`);
  return parsed.value;
}

/**
 * Creates a new PRF-backed passkey, opens the existing wallet seed in the
 * custody worker, and returns ciphertext sealed under the new factor. The
 * seed and both factor secrets stay inside WASM; only the opaque ciphertext
 * crosses back to the caller for the atomic server finalize.
 */
export async function createPasskeyCustodyLinkEnvelope(input: {
  readonly registration: WalletAddAuthMethodRegistrationOptions;
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly existingFactorSecret: Uint8Array;
  readonly worker: WalletCustodyCeremonyTransportPort;
  readonly nowMs?: () => number;
}): Promise<{
  readonly registration: PasskeyRegistrationCredential;
  readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
}> {
  const credential = requireRegistrationCredential(
    await navigator.credentials.create({
      publicKey: publicKeyCreationOptions(input.registration),
    }),
  );
  const registration = serializeRegistrationCredentialWithPRF({
    credential,
    firstPrfOutput: true,
    secondPrfOutput: false,
  });
  const prfFirstB64u = getPrfFirstB64uFromCredential(registration);
  if (!prfFirstB64u) throw new Error('New passkey did not return PRF.first');
  const credentialId = requireCredentialId(credential.id);
  const envelopeIdResult = parsePasskeyEnvelopeId(
    secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
  );
  if (!envelopeIdResult.ok) throw new Error(envelopeIdResult.error.message);
  const factor = buildPasskeyEnvelopeFactor({
    rpId: input.registration.rpId,
    credentialIdB64u: credentialId,
  });
  const replacementBindingJson = JSON.stringify({
    walletId: input.existingEnvelope.walletId,
    envelopeId: envelopeIdResult.value,
    factor,
    envelopeRevision: input.existingEnvelope.envelopeRevision,
    binding: input.existingEnvelope.binding,
  });
  const existingFactorSecret = input.existingFactorSecret.slice();
  const replacementFactorSecret = base64UrlDecode(prfFirstB64u);
  let resealed: ReturnType<typeof requireResealedEnvelope>;
  try {
    const result = await input.worker.requestOperation({
      kind: 'walletCustodyCeremony',
      request: {
        type: 'linkWalletCustodyPasskey',
        payload: {
          existingEnvelope: input.existingEnvelope,
          existingFactorSecret: existingFactorSecret.buffer,
          replacementEnvelopeBindingJson: replacementBindingJson,
          replacementFactorSecret: replacementFactorSecret.buffer,
        },
        transfer: [existingFactorSecret.buffer, replacementFactorSecret.buffer],
      },
    });
    resealed = requireResealedEnvelope(result);
  } finally {
    existingFactorSecret.fill(0);
    replacementFactorSecret.fill(0);
  }
  const nowMs = (input.nowMs ?? Date.now)();
  return {
    registration,
    custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(
      buildPasskeyCustodyEnvelopeRecord({
        envelopeId: envelopeIdResult.value,
        walletId: input.existingEnvelope.walletId,
        binding: input.existingEnvelope.binding,
        factor,
        envelopeRevision: input.existingEnvelope.envelopeRevision,
        nonceB64u: resealed.nonceB64u,
        sealedCustodySecretB64u: resealed.sealedCustodySecretB64u,
        ciphertextDigestB64u: resealed.ciphertextDigestB64u,
        aadHashB64u: resealed.aadHashB64u,
        lifecycle: { state: 'active', activatedAtMs: nowMs },
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
      }),
    ),
  };
}

/** Complete add-passkey custody linking from the browser boundary. */
export async function linkWalletPasskeyCustody(input: {
  readonly relayerUrl: string;
  readonly walletId: Parameters<typeof startWalletAddAuthMethod>[0]['walletId'];
  readonly addAuthMethodIntentGrant: Parameters<typeof startWalletAddAuthMethod>[0]['addAuthMethodIntentGrant'];
  readonly addAuthMethodIntentDigestB64u: string;
  readonly intent: Parameters<typeof startWalletAddAuthMethod>[0]['intent'];
  readonly auth: AddAuthMethodAuth;
  readonly existingFactorSecret: Uint8Array;
  readonly worker: WalletCustodyCeremonyTransportPort;
  readonly nowMs?: () => number;
}): Promise<Awaited<ReturnType<typeof finalizeWalletAddAuthMethod>>> {
  const started = await startWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodIntentGrant: input.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: input.addAuthMethodIntentDigestB64u,
    intent: input.intent,
    auth: input.auth,
    authority: { kind: 'passkey' },
  });
  if (!started.custodyEnvelope || !started.registration) {
    throw new Error('Passkey add-auth-method start omitted custody envelope or registration options');
  }
  const linked = await createPasskeyCustodyLinkEnvelope({
    registration: started.registration,
    existingEnvelope: started.custodyEnvelope,
    existingFactorSecret: input.existingFactorSecret,
    worker: input.worker,
    nowMs: input.nowMs,
  });
  return await finalizeWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    webauthnRegistration: linked.registration,
    custodyEnvelope: linked.custodyEnvelope,
  });
}
