/**
 * The canonical WebAuthn registration options for adding a wallet auth method.
 *
 * This lives in the shared package because three parties read the same record:
 * the server that mints it, the browser that passes it to
 * `navigator.credentials.create`, and — since Refactor 103 Phase 8 — the
 * linked-device target preparation that carries it to Device 2. One
 * declaration, so a change to the ceremony cannot silently diverge from what a
 * linked device creates its passkey against.
 *
 * Everything here is fixed by the canonical add-auth-method ceremony: two
 * algorithms in a fixed order, a resident key, no attestation, and PRF
 * evaluation. Encoding them as literal types rather than open unions is what
 * makes a registration that drifted from the ceremony fail to parse instead of
 * producing a credential nothing can finalize.
 */

import { parseWebAuthnRpId, type WebAuthnRpId } from './domainIds';

export type WalletAddAuthMethodRegistrationOptions = {
  readonly kind: 'webauthn_add_auth_method_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly rpId: WebAuthnRpId;
  readonly user: {
    readonly idB64u: string;
    readonly name: string;
    readonly displayName: string;
  };
  readonly pubKeyCredParams: readonly [
    { readonly type: 'public-key'; readonly alg: -7 },
    { readonly type: 'public-key'; readonly alg: -257 },
  ];
  readonly authenticatorSelection: {
    readonly residentKey: 'required';
    readonly userVerification: 'preferred';
  };
  readonly timeoutMs: number;
  readonly attestation: 'none';
  readonly extensions: {
    readonly prf: {
      readonly eval: {
        readonly firstB64u: string;
        readonly secondB64u: string;
      };
    };
  };
  readonly excludeCredentials: readonly {
    readonly type: 'public-key';
    readonly id: string;
  }[];
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function token(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} must not be empty`);
  if (trimmed !== value) throw new Error(`${label} must not be padded with whitespace`);
  return trimmed;
}

/**
 * The relying party is branded at the boundary rather than at each use, so a
 * consumer cannot verify a credential against an unvalidated host string.
 */
function rpId(value: unknown, label: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(token(value, label));
  if (!parsed.ok) throw new Error(`${label} is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function literal<T extends string | number>(value: unknown, expected: T, label: string): T {
  if (value !== expected) throw new Error(`${label} must be ${String(expected)}`);
  return expected;
}

/**
 * Throws on anything that is not exactly a canonical add-auth-method
 * registration. Callers that need a nullable result wrap this rather than
 * writing a second, looser reading of the same record.
 */
export function parseWalletAddAuthMethodRegistrationOptions(
  raw: unknown,
): WalletAddAuthMethodRegistrationOptions {
  const label = 'WalletAddAuthMethodRegistrationOptions';
  const value = record(raw, label);
  literal(value.kind, 'webauthn_add_auth_method_registration_v1', `${label}.kind`);

  const user = record(value.user, `${label}.user`);
  const selection = record(value.authenticatorSelection, `${label}.authenticatorSelection`);
  const extensions = record(value.extensions, `${label}.extensions`);
  const prf = record(extensions.prf, `${label}.extensions.prf`);
  const prfEval = record(prf.eval, `${label}.extensions.prf.eval`);

  if (!Array.isArray(value.pubKeyCredParams) || value.pubKeyCredParams.length !== 2) {
    throw new Error(`${label}.pubKeyCredParams must list exactly two algorithms`);
  }
  const [first, second] = value.pubKeyCredParams;
  literal(record(first, `${label}.pubKeyCredParams[0]`).type, 'public-key', `${label}.pubKeyCredParams[0].type`);
  literal(record(first, `${label}.pubKeyCredParams[0]`).alg, -7, `${label}.pubKeyCredParams[0].alg`);
  literal(record(second, `${label}.pubKeyCredParams[1]`).type, 'public-key', `${label}.pubKeyCredParams[1].type`);
  literal(record(second, `${label}.pubKeyCredParams[1]`).alg, -257, `${label}.pubKeyCredParams[1].alg`);

  if (!Array.isArray(value.excludeCredentials)) {
    throw new Error(`${label}.excludeCredentials must be an array`);
  }
  const excludeCredentials = value.excludeCredentials.map((entry, index) => {
    const credential = record(entry, `${label}.excludeCredentials[${index}]`);
    return {
      type: literal(credential.type, 'public-key', `${label}.excludeCredentials[${index}].type`),
      id: token(credential.id, `${label}.excludeCredentials[${index}].id`),
    };
  });

  const timeoutMs = value.timeoutMs;
  if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${label}.timeoutMs must be a positive safe integer`);
  }

  return {
    kind: 'webauthn_add_auth_method_registration_v1',
    challengeId: token(value.challengeId, `${label}.challengeId`),
    challengeB64u: token(value.challengeB64u, `${label}.challengeB64u`),
    rpId: rpId(value.rpId, `${label}.rpId`),
    user: {
      idB64u: token(user.idB64u, `${label}.user.idB64u`),
      name: token(user.name, `${label}.user.name`),
      displayName: token(user.displayName, `${label}.user.displayName`),
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: {
      residentKey: literal(
        selection.residentKey,
        'required',
        `${label}.authenticatorSelection.residentKey`,
      ),
      userVerification: literal(
        selection.userVerification,
        'preferred',
        `${label}.authenticatorSelection.userVerification`,
      ),
    },
    timeoutMs,
    attestation: literal(value.attestation, 'none', `${label}.attestation`),
    extensions: {
      prf: {
        eval: {
          firstB64u: token(prfEval.firstB64u, `${label}.extensions.prf.eval.firstB64u`),
          secondB64u: token(prfEval.secondB64u, `${label}.extensions.prf.eval.secondB64u`),
        },
      },
    },
    excludeCredentials,
  };
}
