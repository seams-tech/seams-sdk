/**
 * Refactor 94C. Inline application admission for `/wallets/register/setup`,
 * replacing the stored bootstrap grant.
 *
 * The grant existed so a later route could read back what this check already
 * decided. With setup absorbing intent and start, nothing reads it: the
 * decision is consumed in the same request that makes it, so it is returned
 * rather than persisted. That deletes the stored grant record, its issuance
 * write, and the read-back on the next leg.
 *
 * The two `countIssued` COUNT queries go with it. Rate limiting moves to
 * Cloudflare's edge limiter (94C design rule), and an exact product quota,
 * where a tenant's configured policy requires one, is a single conditional
 * counter update rather than a scan — never two COUNTs on the signup path.
 *
 * Origin, environment, and RP-ID binding are preserved exactly: they are
 * authorization, not bookkeeping.
 */

export type RegistrationSetupAdmissionCredential = {
  readonly apiKeyId: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly quotaBucket?: string | null;
};

export type RegistrationSetupAdmissionResult =
  | { readonly ok: true; readonly credential: RegistrationSetupAdmissionCredential }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly message: string };

export type RegistrationSetupAdmissionPorts = {
  /** Existing publishable-key authentication; unchanged. */
  readonly authenticatePublishableKey: (input: {
    readonly secret: string;
    readonly origin: string;
    readonly environmentId?: string;
  }) => Promise<
    | { readonly ok: true; readonly credential: RegistrationSetupAdmissionCredential }
    | { readonly ok: false; readonly status: number; readonly code: string; readonly message: string }
  >;
  /**
   * Optional exact quota, applied only where a tenant policy requires one.
   * A single conditional decrement; absent means edge rate limiting alone.
   */
  readonly consumeExactQuota?: (input: {
    readonly credential: RegistrationSetupAdmissionCredential;
  }) => Promise<{ readonly ok: true } | { readonly ok: false; readonly message: string }>;
};

/* Mirrors bootstrapGrantBroker's local helpers: this package does not alias
   @shared, and the binding rules must stay byte-identical to the ones the
   grant path enforced. */
function isRpIdAllowedForOrigin(input: { origin: string; rpId: string }): boolean {
  const origin = normalizeOrigin(input.origin);
  const rpId = String(input.rpId || '')
    .trim()
    .toLowerCase();
  if (!origin || !rpId) return false;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    if ((host === 'localhost' || host === '127.0.0.1') && rpId.endsWith('.localhost')) {
      return true;
    }
    return host === rpId || host.endsWith(`.${rpId}`);
  } catch {
    return false;
  }
}

function normalizeOrigin(raw: unknown): string {
  const value = String(raw || '').trim();
  if (!value) return '';
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return '';
  }
}

export async function admitRegistrationSetup(
  ports: RegistrationSetupAdmissionPorts,
  input: {
    readonly publishableKey: string;
    readonly origin: string;
    readonly environmentId: string;
    readonly rpId?: string | null;
  },
): Promise<RegistrationSetupAdmissionResult> {
  const origin = normalizeOrigin(input.origin);
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'publishable_key_origin_blocked',
      message: 'Origin header is required and must be a valid exact origin',
    };
  }

  const authenticated = await ports.authenticatePublishableKey({
    secret: input.publishableKey,
    origin,
    environmentId: input.environmentId,
  });
  if (!authenticated.ok) return authenticated;

  const credential = authenticated.credential;
  if (String(credential.environmentId || '').trim() !== String(input.environmentId || '').trim()) {
    return {
      ok: false,
      status: 403,
      code: 'publishable_key_environment_mismatch',
      message: 'Publishable key is not valid for this environment',
    };
  }

  const rpId = String(input.rpId || '').trim();
  if (rpId && !isRpIdAllowedForOrigin({ origin, rpId })) {
    return {
      ok: false,
      status: 400,
      code: 'invalid_body',
      message: 'rpId is not valid for this origin',
    };
  }

  if (ports.consumeExactQuota) {
    const quota = await ports.consumeExactQuota({ credential });
    if (!quota.ok) {
      return {
        ok: false,
        status: 429,
        code: 'publishable_key_quota_exhausted',
        message: quota.message,
      };
    }
  }

  return { ok: true, credential };
}
