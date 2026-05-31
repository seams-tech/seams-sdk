# Web3Authn SDK

Passkey wallet SDK for NEAR Protocol. An embedded wallet powered by SecureConfirm WebAuthn, cross-origin iframe isolation, and WASM-based cryptography.

Featuring:

- **Core SDK**: Framework-agnostic JavaScript/TypeScript library
- **React Components**: Drop-in components and hooks for React applications
- **Plugins**: plugins to setup the right headers for Vite, Next.js, etc

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
pnpm -C sdk dev       # Watch mode
```

**Test**:

```bash
pnpm -C sdk test           # Playwright tests
pnpm -C sdk run type-check # TypeScript validation
```

## Quick Start

### React Integration

The easiest way to get started with React (React 18+)

```tsx
import { SeamsPasskeyProvider, useSeams } from '@seams/sdk/react';

function App() {
  return (
    <SeamsPasskeyProvider
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
          url: 'https://relay-server.example.com',
        },
      }}
    >
      <YourApp />
    </SeamsPasskeyProvider>
  );
}

function SignInButton() {
  const seams = useSeams();

  const handleSignIn = async () => {
    const result = await seams.registerPasskey('alice.testnet');
    console.log('Registered:', result.success);
  };

  return <button onClick={handleSignIn}>Sign In with Passkey</button>;
}
```

## Vite Plugin Integration

Use the Vite plugins to serve wallet assets in dev and emit the right headers for production.

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { seamsDev, seamsBuildHeaders } from '@seams/sdk/plugins/vite';

export default defineConfig({
  plugins: [
    react(),
    seamsDev({
      walletOrigin: process.env.VITE_WALLET_ORIGIN,
      sdkBasePath: '/sdk',
      walletServicePath: '/wallet-service',
    }),
    seamsBuildHeaders({
      walletOrigin: process.env.VITE_WALLET_ORIGIN,
    }),
  ],
});
```

See `examples/seams-site` and `examples/seams-docs` for full app examples.

## Stable API Surfaces

Use `@seams/sdk` for the main surface (for example `SeamsPasskey` and core types).

Threshold APIs are stable under an explicit subpath:

```ts
import { keygenEcdsa } from '@seams/sdk/threshold';
```

## Configuration Options

```typescript
interface SeamsPasskeyConfig {
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

  // Optional relay server (for account creation & Shamir 3-pass)
  relayer?: {
    url: string;
  };
}
```

## Wallet Iframe Architecture

The SDK isolates all sensitive operations in a cross-origin iframe (e.g., `wallet.web3authn.org`). Your app communicates via secure MessageChannel, but can never access keys directly.

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

```
repo/
├── client/
│   └── src/
│       ├── core/                 # Framework-agnostic client core
│       ├── react/                # React bindings
│       └── plugins/              # Vite/dev helpers
├── server/
│   └── src/
│       └── server/               # Relay backend (routers, storage, threshold)
├── shared/
│   └── src/                      # Cross-platform utils/types
├── wasm/
│   ├── near_signer/              # Rust WASM (NEAR threshold signing)
│   ├── eth_signer/               # Rust WASM (EIP-1559 signing)
│   └── tempo_signer/             # Rust WASM (Tempo tx signing)
├── tests/                        # Playwright + unit tests
└── sdk/
    ├── dist/                     # Build output
    ├── build-paths.ts            # Build configuration (source of truth)
    ├── rolldown.config.ts        # Rolldown bundler config
    ├── scripts/                  # Build/test scripts
    └── README.md                 # This file
```

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Support

- **Documentation**: [../examples/seams-docs/](../examples/seams-docs/)
- **Issues**: [GitHub Issues](https://github.com/web3-authn/sdk/issues)
