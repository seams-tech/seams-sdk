import { SeamsWebProvider, useSeams, type SeamsConfigsInput } from '@seams/wallet/react';

const seamsConfig = {
  iframeWallet: {
    walletOrigin: import.meta.env.VITE_WALLET_ORIGIN,
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
  },
  relayerAccount: 'w3a-relayer.testnet',
  relayer: {
    url: import.meta.env.VITE_RELAYER_URL,
  },
  registration: {
    mode: 'managed',
    projectEnvironmentId: import.meta.env.VITE_SEAMS_PROJECT_ENVIRONMENT_ID,
    publishableKey: import.meta.env.VITE_SEAMS_PUBLISHABLE_KEY,
  },
  chains: [
    {
      network: 'near-testnet',
      rpcUrl: 'https://rpc.testnet.near.org',
      explorerUrl: 'https://testnet.nearblocks.io',
    },
  ],
} satisfies SeamsConfigsInput;

function WalletApp() {
  const { loginState } = useSeams();
  return <p>{loginState.isLoggedIn ? 'Wallet unlocked' : 'Wallet locked'}</p>;
}

export function App() {
  return (
    <SeamsWebProvider config={seamsConfig}>
      <WalletApp />
    </SeamsWebProvider>
  );
}
