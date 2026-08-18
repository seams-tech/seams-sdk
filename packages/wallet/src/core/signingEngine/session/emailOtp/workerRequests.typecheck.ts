import type { EmailOtpWarmSessionTransport } from './workerRequests';

const validEmailOtpWarmSessionTransport = {
  relayerUrl: 'https://relay.example',
  walletSessionToken: 'wallet-session-token',
} satisfies EmailOtpWarmSessionTransport;
void validEmailOtpWarmSessionTransport;
