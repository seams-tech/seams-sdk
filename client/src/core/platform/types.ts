export type PlatformKind = 'browser' | 'ios' | 'linux_embedded';

export type PlatformResult<Ok, Code extends string> =
  | {
      ok: true;
      value: Ok;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code: Code;
      message: string;
      value?: never;
    };

export type DurableRecordStore = {
  kind: 'durable_record_store';
  get<T>(input: { collection: string; key: string }): Promise<PlatformResult<T | null, 'unavailable'>>;
  put<T>(input: { collection: string; key: string; value: T }): Promise<PlatformResult<void, 'unavailable'>>;
  delete(input: { collection: string; key: string }): Promise<PlatformResult<void, 'unavailable'>>;
};

export type SecureSecretStore = {
  kind: 'secure_secret_store';
  seal(input: { purpose: string; secretB64u: string }): Promise<PlatformResult<{ handle: string }, 'unavailable'>>;
  unseal(input: { handle: string }): Promise<PlatformResult<{ secretB64u: string }, 'unavailable' | 'not_found'>>;
  delete(input: { handle: string }): Promise<PlatformResult<void, 'unavailable'>>;
};

export type WebAuthnPrfFirstSecretSource = {
  kind: 'webauthn_prf_first';
  prfFirstB64u: string;
  rpId: string;
  credentialIdB64u: string;
};

export type SecureEnclaveWrappedSecretSource = {
  kind: 'secure_enclave_wrapped_secret';
  keyId: string;
  accessGroup: string;
};

export type Fido2HmacSecretSource = {
  kind: 'fido2_hmac_secret';
  credentialIdB64u: string;
  rpId: string;
};

export type EmailOtpWorkerSessionSecretSource = {
  kind: 'email_otp_worker_session';
  sessionId: string;
};

export type ClientSecretSource =
  | WebAuthnPrfFirstSecretSource
  | SecureEnclaveWrappedSecretSource
  | Fido2HmacSecretSource
  | EmailOtpWorkerSessionSecretSource;

export type AuthenticatorOperation =
  | {
      kind: 'create_passkey';
      rpId: string;
      userHandleB64u: string;
      challengeB64u: string;
    }
  | {
      kind: 'get_passkey';
      rpId: string;
      credentialIdB64u: string;
      challengeB64u: string;
    };

export type AuthenticatorPort = {
  kind: 'authenticator';
  run(
    operation: AuthenticatorOperation,
  ): Promise<PlatformResult<{ credentialIdB64u: string; prfFirstB64u?: string }, 'unavailable' | 'cancelled'>>;
};

export type PrepareEcdsaClientBootstrapInput = {
  secretSource: WebAuthnPrfFirstSecretSource | EmailOtpWorkerSessionSecretSource;
  walletId: string;
  rpId: string;
  participantIds: readonly number[];
};

export type PrepareEcdsaClientBootstrapOutput = {
  stateBlobB64u: string;
  publicFacts: {
    clientPublicKey33B64u: string;
    clientVerifyingShareB64u: string;
    ethereumAddress: `0x${string}`;
  };
  relayerPayload: {
    clientBootstrapB64u: string;
  };
};

export type SignerCryptoPort = {
  kind: 'signer_crypto';
  prepareEcdsaClientBootstrap(
    input: PrepareEcdsaClientBootstrapInput,
  ): Promise<
    PlatformResult<
      PrepareEcdsaClientBootstrapOutput,
      'unsupported_secret_source' | 'invalid_input' | 'crypto_failed' | 'unavailable'
    >
  >;
};

export type HttpTransport = {
  kind: 'http_transport';
  request(input: {
    method: 'GET' | 'POST';
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    timeoutMs?: number;
  }): Promise<PlatformResult<{ status: number; body: unknown }, 'network_error' | 'timeout'>>;
};

export type ClockPort = {
  kind: 'clock';
  nowMs(): number;
};

export type RandomSource = {
  kind: 'random_source';
  randomBytes(length: number): Uint8Array;
};

export type PlatformRuntime = {
  kind: PlatformKind;
  storage: DurableRecordStore;
  secrets: SecureSecretStore;
  authenticator: AuthenticatorPort;
  signerCrypto: SignerCryptoPort;
  http: HttpTransport;
  clock: ClockPort;
  random: RandomSource;
};

export function assertNeverPlatform(value: never): never {
  throw new Error(`Unhandled platform branch: ${String(value)}`);
}

export function platformKindLabel(kind: PlatformKind): string {
  switch (kind) {
    case 'browser':
      return 'Browser';
    case 'ios':
      return 'iOS';
    case 'linux_embedded':
      return 'Linux embedded';
  }
  return assertNeverPlatform(kind);
}
