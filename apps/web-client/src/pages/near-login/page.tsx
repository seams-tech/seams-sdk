import React from 'react';
import { Check, ChevronRight, Loader2, ShieldCheck, Wallet, X } from 'lucide-react';
import { NearConnector } from '@hot-labs/near-connect';
import type {
  Account,
  AccountWithSignedMessage,
  EventMap,
  NearConnector_ConnectOptions,
  NearWalletBase,
  SignedMessage,
} from '@hot-labs/near-connect';

import NearLogo from '@/components/icons/NearLogo';
import { FRONTEND_CONFIG } from '@/config';
import './styles.css';

const POPULAR_WALLET_IDS = [
  'hot-wallet',
  'meteor-wallet',
  'meteor-wallet-app',
  'my-near-wallet',
  'nightly-wallet',
  'near-mobile-wallet',
  'sender',
  'intear-wallet',
  'okx-wallet',
  'wallet-connect',
] as const;

type NearWalletOption = {
  id: string;
  name: string;
  iconUrl: string;
  description: string;
  website: string;
  supportsSignMessage: boolean;
  supportsSignInAndSignMessage: boolean;
  supportsTransactions: boolean;
  rank: number;
};

type Network = 'mainnet' | 'testnet';

type NearLoginChallenge = {
  message: string;
  recipient: string;
  nonce: Uint8Array;
  nonceBase64Url: string;
};

type SignMessageDuringSignInParams = {
  message: string;
  recipient: string;
  nonce: Uint8Array;
};

type NearLoginSession = {
  accountId: string;
  publicKey: string;
  signature: string;
  walletId: string;
  walletName: string;
  walletIconUrl: string;
  message: string;
  recipient: string;
  nonceBase64Url: string;
  wallet: NearWalletBase;
};

type NearLoginState =
  | { tag: 'loading-wallets' }
  | { tag: 'ready'; wallets: readonly NearWalletOption[] }
  | { tag: 'connecting'; wallets: readonly NearWalletOption[]; wallet: NearWalletOption }
  | { tag: 'connected'; wallets: readonly NearWalletOption[]; session: NearLoginSession }
  | { tag: 'failed'; wallets: readonly NearWalletOption[]; message: string };

type WalletPickerState =
  | { tag: 'closed' }
  | { tag: 'open'; wallets: readonly NearWalletOption[]; message: string };

function assertNever(value: never): never {
  throw new Error(`Unhandled NEAR login state: ${JSON.stringify(value)}`);
}

function readNearLoginNetwork(): Network {
  return FRONTEND_CONFIG.nearNetwork === 'mainnet' ? 'mainnet' : 'testnet';
}

function createNearLoginConnector(network: Network): NearConnector {
  return new NearConnector({
    network,
    autoConnect: false,
    footerBranding: null,
    features: {
      signMessage: true,
    },
  });
}

function trimDisplayString(value: unknown, fallback: string): string {
  const trimmed = String(value ?? '').trim();
  return trimmed || fallback;
}

function rankNearWallet(id: string): number {
  const index = POPULAR_WALLET_IDS.findIndex((walletId) => walletId === id);
  return index >= 0 ? index : POPULAR_WALLET_IDS.length + 1;
}

function normalizeNearWalletOption(wallet: NearWalletBase): NearWalletOption {
  const { manifest } = wallet;
  const name = trimDisplayString(manifest.name, manifest.id);
  return {
    id: trimDisplayString(manifest.id, name),
    name,
    iconUrl: trimDisplayString(manifest.icon, ''),
    description: trimDisplayString(manifest.description, 'NEAR wallet'),
    website: trimDisplayString(manifest.website, ''),
    supportsSignMessage: manifest.features.signMessage === true,
    supportsSignInAndSignMessage: manifest.features.signInAndSignMessage === true,
    supportsTransactions:
      manifest.features.signAndSendTransaction === true ||
      manifest.features.signAndSendTransactions === true,
    rank: rankNearWallet(manifest.id),
  };
}

function compareNearWalletOptions(a: NearWalletOption, b: NearWalletOption): number {
  if (a.rank !== b.rank) return a.rank - b.rank;
  return a.name.localeCompare(b.name);
}

function readWalletOptions(connector: NearConnector): readonly NearWalletOption[] {
  return connector.availableWallets
    .map(normalizeNearWalletOption)
    .sort(compareNearWalletOptions);
}

function walletsForState(state: NearLoginState): readonly NearWalletOption[] {
  switch (state.tag) {
    case 'loading-wallets':
      return [];
    case 'ready':
    case 'connecting':
    case 'connected':
    case 'failed':
      return state.wallets;
    default:
      return assertNever(state);
  }
}

function errorMessageFor(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'NEAR wallet connection failed');
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createLoginChallenge(): NearLoginChallenge {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const origin =
    typeof window === 'undefined' ? 'seams.local' : window.location.host || 'seams.local';
  return {
    message: `Sign in to Seams with your NEAR wallet at ${origin}`,
    recipient: origin,
    nonce,
    nonceBase64Url: bytesToBase64Url(nonce),
  };
}

function signMessageParamsFor(challenge: NearLoginChallenge): SignMessageDuringSignInParams {
  return {
    message: challenge.message,
    recipient: challenge.recipient,
    nonce: challenge.nonce,
  };
}

function requireAccount(accounts: readonly Account[]): Account {
  const account = accounts[0];
  if (!account?.accountId) throw new Error('Wallet did not return a NEAR account');
  return account;
}

function requireSignedAccount(accounts: readonly AccountWithSignedMessage[]): AccountWithSignedMessage {
  const account = accounts[0];
  if (!account?.accountId || !account.signedMessage) {
    throw new Error('Wallet did not return a signed NEAR account');
  }
  return account;
}

function buildSession(args: {
  wallet: NearWalletBase;
  option: NearWalletOption;
  accountId: string;
  signedMessage: SignedMessage;
  challenge: NearLoginChallenge;
}): NearLoginSession {
  return {
    accountId: args.accountId,
    publicKey: args.signedMessage.publicKey,
    signature: args.signedMessage.signature,
    walletId: args.option.id,
    walletName: args.option.name,
    walletIconUrl: args.option.iconUrl,
    message: args.challenge.message,
    recipient: args.challenge.recipient,
    nonceBase64Url: args.challenge.nonceBase64Url,
    wallet: args.wallet,
  };
}

function waitForSignedMessageDuringConnect(
  connector: NearConnector,
): Promise<EventMap['wallet:signInAndSignMessage']> {
  return new Promise((resolve) => {
    connector.once('wallet:signInAndSignMessage', resolve);
  });
}

async function connectWithSignInAndMessage(args: {
  connector: NearConnector;
  network: Network;
  option: NearWalletOption;
  challenge: NearLoginChallenge;
}): Promise<NearLoginSession> {
  const eventPromise = waitForSignedMessageDuringConnect(args.connector);
  const connectOptions: NearConnector_ConnectOptions = {
    walletId: args.option.id,
    signMessageParams: signMessageParamsFor(args.challenge),
  };
  const wallet = await args.connector.connect(connectOptions);
  const event = await eventPromise;
  const account = requireSignedAccount(event.accounts);
  return buildSession({
    wallet,
    option: args.option,
    accountId: account.accountId,
    signedMessage: account.signedMessage,
    challenge: args.challenge,
  });
}

async function connectWithSeparateMessageSignature(args: {
  connector: NearConnector;
  network: Network;
  option: NearWalletOption;
  challenge: NearLoginChallenge;
}): Promise<NearLoginSession> {
  const wallet = await args.connector.connect({ walletId: args.option.id });
  const account = requireAccount(await wallet.getAccounts({ network: args.network }));
  const signedMessage = await wallet.signMessage({
    ...signMessageParamsFor(args.challenge),
    network: args.network,
    signerId: account.accountId,
  });
  return buildSession({
    wallet,
    option: args.option,
    accountId: account.accountId,
    signedMessage,
    challenge: args.challenge,
  });
}

async function connectNearWalletForLogin(args: {
  connector: NearConnector;
  network: Network;
  option: NearWalletOption;
}): Promise<NearLoginSession> {
  const challenge = createLoginChallenge();
  if (args.option.supportsSignInAndSignMessage) {
    return connectWithSignInAndMessage({ ...args, challenge });
  }
  return connectWithSeparateMessageSignature({ ...args, challenge });
}

async function disconnectNearLoginSession(args: {
  connector: NearConnector;
  session: NearLoginSession;
}): Promise<void> {
  await args.connector.disconnect(args.session.wallet);
}

function shortenMiddle(value: string): string {
  if (value.length <= 18) return value;
  return `${value.slice(0, 9)}...${value.slice(-7)}`;
}

function createInitialPickerState(): WalletPickerState {
  return { tag: 'closed' };
}

type WalletTileProps = {
  wallet: NearWalletOption;
  disabled: boolean;
  onSelect: (wallet: NearWalletOption) => void;
};

const WalletTile: React.FC<WalletTileProps> = ({ wallet, disabled, onSelect }) => {
  const handleClick = React.useCallback(() => {
    if (disabled) return;
    onSelect(wallet);
  }, [disabled, onSelect, wallet]);

  return (
    <button className="near-login-wallet-tile" type="button" disabled={disabled} onClick={handleClick}>
      <span className="near-login-wallet-tile__icon" aria-hidden>
        {wallet.iconUrl ? <img src={wallet.iconUrl} alt="" /> : <Wallet size={28} />}
      </span>
      <span className="near-login-wallet-tile__body">
        <span className="near-login-wallet-tile__name">{wallet.name}</span>
        <span className="near-login-wallet-tile__meta">
          {wallet.supportsSignInAndSignMessage ? 'One-step signed login' : 'Signed login'}
        </span>
      </span>
      <ChevronRight size={18} aria-hidden />
    </button>
  );
};

type WalletPickerProps = {
  picker: WalletPickerState;
  connectingWalletId: string;
  onClose: () => void;
  onSelect: (wallet: NearWalletOption) => void;
};

const WalletPicker: React.FC<WalletPickerProps> = ({
  picker,
  connectingWalletId,
  onClose,
  onSelect,
}) => {
  if (picker.tag === 'closed') return null;

  const hasWallets = picker.wallets.length > 0;
  return (
    <div className="near-login-modal-backdrop" role="presentation">
      <section
        className="near-login-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="near-login-wallet-title"
      >
        <div className="near-login-modal__header">
          <h2 id="near-login-wallet-title">Choose your NEAR wallet</h2>
          <button className="near-login-icon-button" type="button" onClick={onClose} aria-label="Close">
            <X size={22} aria-hidden />
          </button>
        </div>

        {picker.message ? <p className="near-login-modal__message">{picker.message}</p> : null}

        {hasWallets ? (
          <div className="near-login-wallet-grid">
            {picker.wallets.map((wallet) => (
              <WalletTile
                key={wallet.id}
                wallet={wallet}
                disabled={connectingWalletId === wallet.id}
                onSelect={onSelect}
              />
            ))}
          </div>
        ) : (
          <div className="near-login-empty">
            <Wallet size={30} aria-hidden />
            <p>No compatible NEAR wallets were found for this network.</p>
          </div>
        )}
      </section>
    </div>
  );
};

type ConnectedPanelProps = {
  session: NearLoginSession;
  onDisconnect: () => void;
};

const ConnectedPanel: React.FC<ConnectedPanelProps> = ({ session, onDisconnect }) => (
  <section className="near-login-connected" aria-label="Connected NEAR wallet">
    <div className="near-login-connected__status">
      <span className="near-login-connected__check" aria-hidden>
        <Check size={18} />
      </span>
      <span>Wallet connected</span>
    </div>
    <div className="near-login-connected__wallet">
      <span className="near-login-connected__icon" aria-hidden>
        {session.walletIconUrl ? <img src={session.walletIconUrl} alt="" /> : <Wallet size={24} />}
      </span>
      <div>
        <strong>{session.walletName}</strong>
        <span>{session.accountId}</span>
      </div>
    </div>
    <dl className="near-login-proof">
      <div>
        <dt>Public key</dt>
        <dd>{shortenMiddle(session.publicKey)}</dd>
      </div>
      <div>
        <dt>Signature</dt>
        <dd>{shortenMiddle(session.signature)}</dd>
      </div>
      <div>
        <dt>Nonce</dt>
        <dd>{shortenMiddle(session.nonceBase64Url)}</dd>
      </div>
    </dl>
    <button className="near-login-secondary-button" type="button" onClick={onDisconnect}>
      Disconnect
    </button>
  </section>
);

export function NearLoginPage(): React.JSX.Element {
  const network = React.useMemo(readNearLoginNetwork, []);
  const connector = React.useMemo(() => createNearLoginConnector(network), [network]);
  const [state, setState] = React.useState<NearLoginState>({ tag: 'loading-wallets' });
  const [picker, setPicker] = React.useState<WalletPickerState>(createInitialPickerState);

  const refreshWallets = React.useCallback(() => {
    const wallets = readWalletOptions(connector);
    setState((current) => {
      switch (current.tag) {
        case 'loading-wallets':
        case 'ready':
        case 'failed':
          return { tag: 'ready', wallets };
        case 'connecting':
          return { ...current, wallets };
        case 'connected':
          return { ...current, wallets };
        default:
          return assertNever(current);
      }
    });
  }, [connector]);

  React.useEffect(() => {
    let active = true;
    const refreshIfActive = () => {
      if (!active) return;
      refreshWallets();
    };

    connector.on('selector:walletsChanged', refreshIfActive);
    connector.whenManifestLoaded.then(refreshIfActive).catch(() => {
      if (!active) return;
      setState({ tag: 'failed', wallets: [], message: 'Unable to load NEAR wallet manifest' });
    });

    return () => {
      active = false;
      connector.off('selector:walletsChanged', refreshIfActive);
    };
  }, [connector, refreshWallets]);

  const openWalletPicker = React.useCallback(() => {
    const wallets = walletsForState(state);
    setPicker({
      tag: 'open',
      wallets,
      message:
        wallets.length === 0
          ? 'Install a supported NEAR wallet or try again after the manifest loads.'
          : '',
    });
  }, [state]);

  const closeWalletPicker = React.useCallback(() => {
    setPicker({ tag: 'closed' });
  }, []);

  const selectWallet = React.useCallback(
    async (wallet: NearWalletOption) => {
      const wallets = walletsForState(state);
      setPicker({ tag: 'closed' });
      setState({ tag: 'connecting', wallets, wallet });
      try {
        const session = await connectNearWalletForLogin({ connector, network, option: wallet });
        setState({ tag: 'connected', wallets: readWalletOptions(connector), session });
      } catch (error: unknown) {
        setState({
          tag: 'failed',
          wallets: readWalletOptions(connector),
          message: errorMessageFor(error),
        });
      }
    },
    [connector, network, state],
  );

  const disconnect = React.useCallback(async () => {
    if (state.tag !== 'connected') return;
    try {
      await disconnectNearLoginSession({ connector, session: state.session });
      setState({ tag: 'ready', wallets: readWalletOptions(connector) });
    } catch (error: unknown) {
      setState({
        tag: 'failed',
        wallets: readWalletOptions(connector),
        message: errorMessageFor(error),
      });
    }
  }, [connector, state]);

  const wallets = walletsForState(state);
  const connectingWalletId = state.tag === 'connecting' ? state.wallet.id : '';
  const walletCountLabel = wallets.length === 1 ? '1 wallet available' : `${wallets.length} wallets available`;
  const actionDisabled = state.tag === 'loading-wallets' || state.tag === 'connecting';

  return (
    <main className="near-login-page" aria-label="NEAR login">
      <a className="near-login-brand" href="https://near.org" aria-label="NEAR home">
        <span className="near-login-brand__mark">
          <NearLogo size={34} />
        </span>
        <span>near</span>
      </a>

      <section className="near-login-shell" aria-labelledby="near-login-title">
        <div className="near-login-copy">
          <p className="near-login-eyebrow">{network}</p>
          <h1 id="near-login-title">Sign in or create an account</h1>
          <p>
            Use an existing NEAR wallet to continue with a signed login proof from the selected
            account.
          </p>
        </div>

        <div className="near-login-actions" aria-label="Login methods">
          <button
            className="near-login-primary-button"
            type="button"
            onClick={openWalletPicker}
            disabled={actionDisabled}
          >
            <span className="near-login-primary-button__icon" aria-hidden>
              {state.tag === 'loading-wallets' || state.tag === 'connecting' ? (
                <Loader2 size={20} className="near-login-spin" />
              ) : (
                <Wallet size={20} />
              )}
            </span>
            <span>Continue with NEAR wallet</span>
          </button>
          <div className="near-login-method-note">
            <ShieldCheck size={18} aria-hidden />
            <span>{state.tag === 'loading-wallets' ? 'Loading wallet manifest' : walletCountLabel}</span>
          </div>
        </div>

        {state.tag === 'failed' ? (
          <div className="near-login-error" role="alert">
            {state.message}
          </div>
        ) : null}

        {state.tag === 'connected' ? (
          <ConnectedPanel session={state.session} onDisconnect={disconnect} />
        ) : null}
      </section>

      <WalletPicker
        picker={picker}
        connectingWalletId={connectingWalletId}
        onClose={closeWalletPicker}
        onSelect={selectWallet}
      />
    </main>
  );
}

export default NearLoginPage;
