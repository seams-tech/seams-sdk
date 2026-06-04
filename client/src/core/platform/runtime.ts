
import type { HttpTransport } from './http';
import type {
  AuthenticatorPort,
  DurableRecordStore,
  SecureSecretStore,
  SignerCryptoPort,
} from './ports';

export type PlatformKind = 'browser' | 'ios' | 'linux_embedded';

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

export type EmbeddedPlatformRuntime = PlatformRuntime & {
  kind: 'linux_embedded';
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
