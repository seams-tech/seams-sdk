import {
  buildMethodBoundEnvelopeOwnership,
  buildPasskeyCustodyEnvelopeRecord,
  custodyEnvelopeBindingJsonV1,
  buildPasskeyEnvelopeFactor,
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '@shared/passkey-custody';
import { base64UrlDecode } from '@shared/utils/base64';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parsePasskeyEnvelopeId,
  parseWebAuthnCredentialIdB64u,
  type WalletAuthMethodId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  finalizeWalletAddAuthMethod,
  startWalletAddAuthMethod,
  type AddAuthMethodAuth,
  type WalletAddAuthMethodRegistrationOptions,
} from '@/core/rpcClients/relayer/walletRegistration';
import { serializeRegistrationCredentialWithPRF } from '../webauthnAuth/credentials/helpers';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { getPrfFirstB64uFromCredential } from '../webauthnAuth/credentials/credentialExtensions';
import type { WalletCustodyCeremonyTransportPort } from './ceremonyStepRunner';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '../workerManager/workerTypes';

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
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly sealedCustodySecretB64u: EnvelopeCiphertextB64u;
  readonly aadHashB64u: DigestB64u;
  readonly ciphertextDigestB64u: DigestB64u;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Passkey custody worker returned no resealed envelope');
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

function requireUnlockedCapabilitySource(
  source: WalletCustodySealSourceV1,
): UnlockedWalletEd25519ExportRootCapabilityV1 {
  if (source.kind !== 'unlocked_capability') {
    throw new Error('wallet custody reseal source is not an unlocked capability');
  }
  return source.capability;
}

function requireCredentialId(value: string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(value);
  if (!parsed.ok)
    throw new Error(`Passkey registration credential id is invalid: ${parsed.error.message}`);
  return parsed.value;
}

/**
 * Where the seed being resealed comes from.
 *
 * A Passkey source hands over the PRF it just collected. An Email OTP source
 * hands over nothing: its factor secret is already parked in the worker by the
 * unlock that opened this session, so the addition costs no factor release and
 * no second one-time code. Either way the worker opens the seed and reseals it;
 * only the door differs.
 */
export type WalletCustodySealSourceV1 =
  | { readonly kind: 'factor_secret'; readonly existingFactorSecret: Uint8Array }
  | {
      readonly kind: 'unlocked_capability';
      readonly capability: UnlockedWalletEd25519ExportRootCapabilityV1;
    };

/**
 * Creates a new PRF-backed passkey, opens the existing wallet seed in the
 * custody worker, and returns ciphertext sealed under the new factor. The
 * seed and both factor secrets stay inside WASM; only the opaque ciphertext
 * crosses back to the caller for the atomic server finalize.
 */
export async function createPasskeyCustodyLinkEnvelope(input: {
  readonly registration: WalletAddAuthMethodRegistrationOptions;
  /** The server-allocated target method this envelope will belong to. */
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly registrationCredential?: WebAuthnRegistrationCredential;
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly sealSource: WalletCustodySealSourceV1;
  readonly worker: WalletCustodyCeremonyTransportPort;
  readonly nowMs?: () => number;
}): Promise<{
  readonly registration: PasskeyRegistrationCredential;
  readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
}> {
  const registration = input.registrationCredential
    ? input.registrationCredential
    : serializeRegistrationCredentialWithPRF({
        credential: requireRegistrationCredential(
          await navigator.credentials.create({
            publicKey: publicKeyCreationOptions(input.registration),
          }),
        ),
        firstPrfOutput: true,
        secondPrfOutput: false,
      });
  const prfFirstB64u = getPrfFirstB64uFromCredential(registration);
  if (!prfFirstB64u) throw new Error('New passkey did not return PRF.first');
  const credentialId = requireCredentialId(registration.rawId || registration.id);
  const envelopeIdResult = parsePasskeyEnvelopeId(
    secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
  );
  if (!envelopeIdResult.ok) throw new Error(envelopeIdResult.error.message);
  const factor = buildPasskeyEnvelopeFactor({
    rpId: input.registration.rpId,
    credentialIdB64u: credentialId,
  });
  const ownership = buildMethodBoundEnvelopeOwnership(input.walletAuthMethodId);
  const replacementBindingJson = custodyEnvelopeBindingJsonV1({
    walletId: input.existingEnvelope.walletId,
    envelopeId: envelopeIdResult.value,
    factor,
    envelopeRevision: parseEnvelopeRevision(1),
    binding: input.existingEnvelope.binding,
    ownership,
  });
  const replacementFactorSecret = base64UrlDecode(prfFirstB64u);
  const existingFactorSecret =
    input.sealSource.kind === 'factor_secret'
      ? input.sealSource.existingFactorSecret.slice()
      : null;
  let resealed: ReturnType<typeof requireResealedEnvelope>;
  try {
    const result =
      existingFactorSecret === null
        ? await input.worker.requestOperation({
            kind: 'walletCustodyCeremony',
            request: {
              type: 'resealWalletCustodyFromUnlockedCapability',
              payload: {
                capability: requireUnlockedCapabilitySource(input.sealSource),
                replacementEnvelopeBindingJson: replacementBindingJson,
                replacementFactorSecret: replacementFactorSecret.buffer,
              },
              transfer: [replacementFactorSecret.buffer],
            },
          })
        : await input.worker.requestOperation({
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
    /* Transferred buffers are detached; zeroing one throws. */
    if (existingFactorSecret && existingFactorSecret.byteLength > 0) existingFactorSecret.fill(0);
    if (replacementFactorSecret.byteLength > 0) replacementFactorSecret.fill(0);
  }
  const nowMs = (input.nowMs ?? Date.now)();
  return {
    registration,
    custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(
      buildPasskeyCustodyEnvelopeRecord({
        envelopeId: envelopeIdResult.value,
        walletId: input.existingEnvelope.walletId,
        ownership,
        binding: input.existingEnvelope.binding,
        factor,
        envelopeRevision: parseEnvelopeRevision(1),
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

/**
 * Start-only add-passkey: mint the ceremony without finalizing it.
 *
 * Refactor 103 Phase 8 splits an add-auth-method ceremony across two machines.
 * Device 1 has the owner authority to start one; Device 2 holds the PRF that
 * finalizes it. `linkWalletPasskeyCustody` below does both halves in one call
 * because it runs where a single device holds both — which is exactly what
 * device linking does not have.
 *
 * So this half stops at the ceremony. It creates the intent, proves owner
 * authority freshly against that intent's digest, starts the ceremony, and
 * returns its identity — plus the custody envelope the start hands back, which
 * Device 1 holds and later seals for the linked device. It deliberately does
 * not create a credential and never accepts an existing factor secret: the
 * secret that opens that envelope is PRF.first from the assertion the caller
 * already collected, and the seed reaches Device 2 by the sealed custody
 * transfer rather than through this function.
 */
export async function startWalletPasskeyAddAuthMethodCeremony(input: {
  readonly relayerUrl: string;
  readonly walletId: Parameters<typeof startWalletAddAuthMethod>[0]['walletId'];
  readonly addAuthMethodIntentGrant: Parameters<
    typeof startWalletAddAuthMethod
  >[0]['addAuthMethodIntentGrant'];
  readonly addAuthMethodIntentDigestB64u: string;
  readonly intent: Parameters<typeof startWalletAddAuthMethod>[0]['intent'];
  readonly auth: AddAuthMethodAuth;
}): Promise<{
  readonly addAuthMethodCeremonyId: string;
  readonly registration: WalletAddAuthMethodRegistrationOptions;
  readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly expiresAtMs: number;
}> {
  const started = await startWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodIntentGrant: input.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: input.addAuthMethodIntentDigestB64u,
    intent: input.intent,
    auth: input.auth,
    authority: { kind: 'passkey' },
  });
  if (
    !started.registration ||
    !started.custodyEnvelope ||
    started.addAuthMethodCeremonyExpiresAtMs === undefined
  ) {
    throw new Error(
      'Passkey add-auth-method start omitted registration options, custody envelope, or expiry',
    );
  }
  return {
    addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    registration: started.registration,
    custodyEnvelope: started.custodyEnvelope,
    expiresAtMs: started.addAuthMethodCeremonyExpiresAtMs,
  };
}

/** Complete add-passkey custody linking from the browser boundary. */
export async function linkWalletPasskeyCustody(input: {
  readonly relayerUrl: string;
  readonly walletId: Parameters<typeof startWalletAddAuthMethod>[0]['walletId'];
  readonly addAuthMethodIntentGrant: Parameters<
    typeof startWalletAddAuthMethod
  >[0]['addAuthMethodIntentGrant'];
  readonly addAuthMethodIntentDigestB64u: string;
  readonly intent: Parameters<typeof startWalletAddAuthMethod>[0]['intent'];
  readonly auth: AddAuthMethodAuth;
  readonly sealSource: WalletCustodySealSourceV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly worker: WalletCustodyCeremonyTransportPort;
  readonly createRegistrationCredential?: (
    registration: WalletAddAuthMethodRegistrationOptions,
  ) => Promise<WebAuthnRegistrationCredential>;
  readonly nowMs?: () => number;
}): Promise<{
  readonly finalized: Awaited<ReturnType<typeof finalizeWalletAddAuthMethod>>;
  readonly registration: PasskeyRegistrationCredential;
}> {
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
    throw new Error(
      'Passkey add-auth-method start omitted custody envelope or registration options',
    );
  }
  const linked = await createPasskeyCustodyLinkEnvelope({
    registration: started.registration,
    walletAuthMethodId: input.walletAuthMethodId,
    existingEnvelope: started.custodyEnvelope,
    sealSource: input.sealSource,
    worker: input.worker,
    ...(input.createRegistrationCredential
      ? { registrationCredential: await input.createRegistrationCredential(started.registration) }
      : {}),
    nowMs: input.nowMs,
  });
  const finalized = await finalizeWalletAddAuthMethod({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    webauthnRegistration: linked.registration,
    custodyEnvelope: linked.custodyEnvelope,
  });
  return { finalized, registration: linked.registration };
}
