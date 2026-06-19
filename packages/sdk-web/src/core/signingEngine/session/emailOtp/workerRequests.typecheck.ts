import type { EmailOtpWarmSessionTransport } from './workerRequests';

const validEmailOtpWarmSessionTransport = {
  relayerUrl: 'https://relay.example',
  walletSessionJwt: 'wallet-session-jwt',
} satisfies EmailOtpWarmSessionTransport;
void validEmailOtpWarmSessionTransport;

const invalidEmailOtpWarmSessionTransportWithOldTokenField = {
  relayerUrl: 'https://relay.example',
  // @ts-expect-error Email OTP worker transports use walletSessionJwt.
  thresholdSessionAuthToken: 'wallet-session-jwt',
} satisfies EmailOtpWarmSessionTransport;
void invalidEmailOtpWarmSessionTransportWithOldTokenField;
