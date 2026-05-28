export type {
  AuthenticatorOperation,
  AuthenticatorPort,
  ClientSecretSource,
  ClockPort,
  DurableRecordStore,
  EmailOtpWorkerSessionSecretSource,
  Fido2HmacSecretSource,
  HttpTransport,
  PlatformKind,
  PlatformResult,
  PlatformRuntime,
  PrepareEcdsaClientBootstrapInput,
  PrepareEcdsaClientBootstrapOutput,
  RandomSource,
  SecureEnclaveWrappedSecretSource,
  SecureSecretStore,
  SignerCryptoPort,
  WebAuthnPrfFirstSecretSource,
} from './types';
export { assertNeverPlatform, platformKindLabel } from './types';
export {
  createBrowserPlatformRuntime,
  getBrowserPlatformIndexedDB,
  type BrowserDurableRecordStore,
  type BrowserPlatformRuntime,
} from './browser/createBrowserPlatformRuntime';
