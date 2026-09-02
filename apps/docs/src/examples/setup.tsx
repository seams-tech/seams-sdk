import { SeamsWebProvider, seamsTestnetConfig, useSeams } from '@seams/wallet/react';

// Everything else — wallet service path, SDK base path, relayer account, chain
// RPC and explorer URLs — comes from the SDK defaults.
const seamsConfig = seamsTestnetConfig({
  walletOrigin: import.meta.env.VITE_WALLET_ORIGIN,
  relayerUrl: import.meta.env.VITE_RELAYER_URL,
  publishableKey: import.meta.env.VITE_SEAMS_PUBLISHABLE_KEY,
});

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
