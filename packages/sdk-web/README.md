# Web3Authn SDK

Passkey wallet SDK for NEAR Protocol. An embedded wallet powered by
SecureConfirm WebAuthn, cross-origin iframe isolation, and WASM-based
cryptography.

Featuring:

- **Core SDK**: Framework-agnostic JavaScript/TypeScript library
- **React Components**: Drop-in components and hooks for React applications
- **Hosted wallet runtime**: static wallet-service, worker, WASM, and export
  viewer support assets for the wallet origin

## Installation

Install the published package:

```bash
npm install @seams/sdk
# or
pnpm add @seams/sdk
# or
yarn add @seams/sdk
```

### For SDK Developers

**Build**:

```bash
# From repo root
pnpm install
pnpm build:wasm       # Builds Rust/WASM packages
pnpm build:sdk        # Builds SDK dist from existing WASM outputs
pnpm build:sdk-full   # Builds WASM packages + SDK dist
pnpm -C packages/sdk-web dev       # Watch mode
```

**Test**:

```bash
pnpm -C packages/sdk-web test           # Playwright tests
pnpm -C packages/sdk-web run type-check # TypeScript validation
```

## Quick Start

### React Integration

The easiest way to get started with React (React 18+)

```tsx
import { SeamsWebProvider, useSeams } from '@seams/sdk/react';

function App() {
  return (
    <SeamsWebProvider
      config={{
        chains: [
          {
            network: 'near-testnet',
            rpcUrl: 'https://rpc.testnet.near.org',
            explorerUrl: 'https://testnet.nearblocks.io',
          },
        ],
        iframeWallet: {
          walletOrigin: 'https://wallet.web3authn.org',
        },
        relayer: {
          url: 'https://router-api.example.com',
        },
      }}
    >
      <YourApp />
    </SeamsWebProvider>
  );
}

function SignInButton() {
  const seams = useSeams();

  const handleSignIn = async () => {
    const result = await seams.registerPasskey();
    console.log('Registered:', result.success);
  };

  return <button onClick={handleSignIn}>Sign In with Passkey</button>;
}
```

### Google SSO + Email OTP Wallet Auth

For the standard Google SSO plus Email OTP wallet flow, the app owns Google
Identity token acquisition and the SDK owns wallet registration, unlock,
challenge routing, signing-session readiness, and wallet-iframe routing.

```tsx
import { SeamsAuthMenu } from '@seams/sdk/react';

function AuthMenu() {
  const seams = useSeams();

  return (
    <SeamsAuthMenu
      socialLogin={{
        google: async ({ mode, emailOtpAuthPolicy }) => {
          const idToken = await getGoogleIdTokenFromYourApp();
          const flow = await seams.auth.beginGoogleEmailOtpWalletAuth({
            idToken,
            mode,
            sessionKind: 'jwt',
            emailOtpAuthPolicy,
          });
          if (!flow.ok) throw new Error(flow.error.message);
          return {
            kind: 'otp_flow',
            flow: flow.value,
            onComplete: async ({ walletId }) => {
              console.log('Wallet ready:', walletId);
            },
          };
        },
      }}
    />
  );
}
```

When the wallet runs in iframe mode, `SeamsAuthMenu` renders the passkey
registration CTA through the wallet iframe activation surface. The visible
wrapper keeps the app's normal styling, while the wallet-origin iframe owns the
actual click that opens WebAuthn. Direct SDK calls such as
`seams.registerPasskey()` keep the wallet-origin confirmation modal so the user
can click inside the iframe before Touch ID or the platform authenticator prompt
appears.

The public flow only exposes UI-safe data: wallet id, email hint, prompt copy,
delivery status, expiry, and `resend`/`reroll`/`submit`/`cancel` methods. It
does not expose app-session JWTs, runtime policy scope, recovery codes, or
ECDSA bootstrap material.

Low-level Email OTP methods such as `requestEmailOtpChallenge`,
`requestEmailOtpEnrollmentChallenge`, `enrollEmailOtp`, and
`loginWithEmailOtpEcdsaCapability` remain available for advanced custom
integrations. Prefer `beginGoogleEmailOtpWalletAuth` for the standard Google
SSO wallet registration and login path.

In wallet-iframe mode, the same public API is used by the app origin. The wallet
origin owns Email OTP recovery-code backup UI, acknowledgement, workers, sealed
refresh state, and threshold-session state. App-origin iframe responses carry
only non-secret flow metadata and submit results.

## Hosted Wallet Integration

Applications import the SDK as package code and configure the hosted wallet
origin. They do not serve Seams wallet assets from the app Vite config.

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
});
```

During the stabilization milestone, configure the hosted wallet through the
existing `iframeWallet` surface:

```typescript
const config = {
  relayer: { url: 'https://router.example.com' },
  iframeWallet: {
    walletOrigin: 'https://sign.seams.sh',
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
  },
};
```

The Seams-operated wallet origin serves `/wallet-service`, `/sdk/*`, and
`/sdk/workers/*` from `@seams/sdk/dist/public`. Private-key export uses a
wallet-origin inline viewer document that loads its support files from `/sdk/*`.
App origins should not route those paths.

The SDK-created wallet iframe carries the default WebAuthn delegation through
its `allow` attribute. App-platform `Permissions-Policy` should only be added
if hosted-origin browser smokes prove a supported browser requires it.

## Stable API Surfaces

Use `@seams/sdk` for the main surface (for example `SeamsWeb` and core types).

Threshold APIs are stable under an explicit subpath:

```ts
import { keygenEcdsa } from '@seams/sdk/threshold';
```

## Configuration Options

```typescript
interface SeamsWebConfig {
  // Chain settings
  chains: Array<{
    network:
      | 'near-mainnet'
      | 'near-testnet'
      | 'tempo-mainnet'
      | 'tempo-testnet'
      | 'arc-mainnet'
      | 'arc-testnet';
    rpcUrl: string;
    explorerUrl: string;
    chainId?: number; // EVM (arc-*) chains only
  }>;
  relayerAccount: string; // Parent account used for new subaccounts

  // Wallet iframe settings (recommended)
  iframeWallet?: {
    walletOrigin: string; // e.g., 'https://wallet.web3authn.org'
    walletServicePath?: string; // Default: '/wallet-service'
    sdkBasePath?: string; // Default: '/sdk'
    walletHostVariant?: 'runtime' | 'full' | 'near' | 'ecdsa'; // Default: 'runtime'
    rpIdOverride?: string; // Optional: Credential scope override
  };

  // Optional Router API server (for account creation & Shamir 3-pass)
  relayer?: {
    url: string;
  };
}
```

## Wallet Iframe Architecture

The SDK isolates all sensitive operations in a cross-origin iframe such as
`wallet.web3authn.org`. Your app communicates via secure MessageChannel, and app
code cannot access keys directly.

### Configuration

**Recommended** (dedicated wallet origin):

```tsx
iframeWallet: {
  walletOrigin: 'https://wallet.web3authn.org',
  walletServicePath: '/wallet-service',
  walletHostVariant: 'runtime',
}
```

## Project Structure

```text
repo/
├── apps/
│   ├── web-client/               # Browser app/site
│   ├── web-server/               # Deployable Router API server app
│   └── docs/                     # Documentation app
├── packages/
│   ├── sdk-web/                  # Browser SDK package and build output
│   ├── sdk-server-ts/            # Server library source
│   └── shared-ts/                # Shared TypeScript utils/types
├── clients/
│   └── ios/                      # Swift iOS client package
├── crates/
│   ├── signer-core/              # Shared signer core primitives
│   └── seams-embedded/           # Embedded Rust SDK facade
├── wasm/                         # Rust WASM packages
└── tests/                        # Playwright + unit tests
```

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Support

- **Documentation**: [../../apps/docs/](../../apps/docs/)
- **Issues**: [GitHub Issues](https://github.com/web3-authn/sdk/issues)
