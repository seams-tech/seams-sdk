import type {
  RouterApiBootstrapGrantClientContext,
  RouterApiBootstrapGrantFailureCode,
  RouterApiBootstrapGrantIssueAuthority,
  RouterApiBootstrapGrantIssueRequest,
} from './routerApi';

export class RouterApiBootstrapGrantError extends Error {
  readonly code: RouterApiBootstrapGrantFailureCode;
  readonly status: 400 | 409;

  constructor(input: {
    code: RouterApiBootstrapGrantFailureCode;
    status: 400 | 409;
    message: string;
  }) {
    super(input.message);
    this.name = 'RouterApiBootstrapGrantError';
    this.code = input.code;
    this.status = input.status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readRequiredString(source: Record<string, unknown>, key: string): string {
  const value = String(source[key] ?? '').trim();
  if (!value) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: `Missing required field: ${key}`,
    });
  }
  return value;
}

function readOptionalString(source: Record<string, unknown>, key: string): string | undefined {
  const value = String(source[key] ?? '').trim();
  return value || undefined;
}

function hasOwnField(source: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(source, key);
}

function normalizeClientContext(input: unknown): RouterApiBootstrapGrantClientContext | undefined {
  if (!isRecord(input)) return undefined;
  const sdk = String(input.sdk || '').trim();
  const sdkVersion = String(input.sdkVersion || '').trim();
  const userAgentHint = String(input.userAgentHint || '').trim();
  if (!sdk && !sdkVersion && !userAgentHint) return undefined;
  return {
    ...(sdk ? { sdk } : {}),
    ...(sdkVersion ? { sdkVersion } : {}),
    ...(userAgentHint ? { userAgentHint } : {}),
  };
}

function normalizeRegistrationBootstrapGrantFlow(raw: unknown): 'registration_v1' {
  const flow = String(raw || '').trim();
  if (flow !== 'registration_v1') {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Field flow must be "registration_v1"',
    });
  }
  return 'registration_v1';
}

function parseBootstrapGrantIssueAuthority(raw: unknown): RouterApiBootstrapGrantIssueAuthority {
  if (!isRecord(raw)) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Missing required field: authority',
    });
  }
  const kind = readRequiredString(raw, 'kind');
  switch (kind) {
    case 'passkey_rp':
      return {
        kind: 'passkey_rp',
        rpId: readRequiredString(raw, 'rpId'),
      };
    case 'wallet_auth':
      if (hasOwnField(raw, 'rpId')) {
        throw new RouterApiBootstrapGrantError({
          code: 'invalid_body',
          status: 400,
          message: 'Wallet-auth bootstrap grant authority must not include rpId',
        });
      }
      return { kind: 'wallet_auth' };
    default:
      throw new RouterApiBootstrapGrantError({
        code: 'invalid_body',
        status: 400,
        message: 'Field authority.kind must be "passkey_rp" or "wallet_auth"',
      });
  }
}

export function parseRouterApiBootstrapGrantIssueBody(
  body: unknown,
): Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey' | 'origin'> {
  if (!isRecord(body)) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Expected JSON object request body',
    });
  }
  const environmentId = readRequiredString(body, 'environmentId');
  const newAccountId = readOptionalString(body, 'newAccountId');
  if (hasOwnField(body, 'rpId')) {
    throw new RouterApiBootstrapGrantError({
      code: 'invalid_body',
      status: 400,
      message: 'Root field rpId is not valid on bootstrap grant requests',
    });
  }
  const flow = normalizeRegistrationBootstrapGrantFlow(body.flow);
  const clientContext = normalizeClientContext(body.clientContext);
  const authority = parseBootstrapGrantIssueAuthority(body.authority);
  if (newAccountId && clientContext) {
    return {
      environmentId,
      newAccountId,
      authority,
      flow,
      clientContext,
    };
  }
  if (newAccountId) {
    return {
      environmentId,
      newAccountId,
      authority,
      flow,
    };
  }
  if (clientContext) {
    return {
      environmentId,
      authority,
      flow,
      clientContext,
    };
  }
  return {
    environmentId,
    authority,
    flow,
  };
}
