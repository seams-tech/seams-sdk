import React from 'react';
import {
  ActionType,
  useSeams,
  type GoogleEmailOtpWalletAuthEcdsaTargets,
  type RegistrationResult,
  type RegistrationSignerSetSelection,
  type WalletIframeRegistrationActivationSurface,
} from '@seams/sdk/react';
import {
  encodeSignedTransactionBase64,
  nearAccountRefFromAccountId,
  parseWebAuthnRpId,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  walletSessionRefFromSession,
} from '@seams/sdk/advanced';

type IntendedActionName =
  | 'registerPasskeyWallet'
  | 'registerPasskeyEd25519YaoWallet'
  | 'registerPreparedIframePasskeyEd25519YaoWallet'
  | 'addPasskeyEd25519YaoWalletSigner'
  | 'registerEmailOtpWallet'
  | 'unlockPasskeyWallet'
  | 'unlockEmailOtpWallet'
  | 'signNearTransaction'
  | 'signTempoTransaction'
  | 'signArcEvmTransaction'
  | 'exportEd25519Key'
  | 'exportEcdsaKey';

type IntendedLifecycleEvent = {
  index: number;
  payload: unknown;
};

type IntendedActionIdle = {
  status: 'idle';
  action?: never;
  result?: never;
  error?: never;
};

type IntendedActionRunning = {
  status: 'running';
  action: IntendedActionName;
  result?: never;
  error?: never;
};

type IntendedEcdsaTargetKeySummary = {
  chain: 'tempo' | 'arc_evm';
  chainId: number;
  thresholdOwnerAddress: string;
};

type IntendedEcdsaTargetProfileName = 'none' | 'tempo' | 'tempo_arc';

type IntendedEcdsaTargetKeysSummary =
  | {
      kind: 'none';
      tempo?: never;
      arcEvm?: never;
    }
  | {
      kind: 'tempo';
      tempo: IntendedEcdsaTargetKeySummary;
      arcEvm?: never;
    }
  | {
      kind: 'tempo_arc';
      tempo: IntendedEcdsaTargetKeySummary;
      arcEvm: IntendedEcdsaTargetKeySummary;
    };

type IntendedEmailOtpEcdsaTargetProfile =
  | {
      kind: 'none';
      sdkTargets: Extract<GoogleEmailOtpWalletAuthEcdsaTargets, { kind: 'none' }>;
      chainTargets: readonly [];
    }
  | {
      kind: 'tempo';
      sdkTargets: Extract<GoogleEmailOtpWalletAuthEcdsaTargets, { kind: 'explicit' }>;
      chainTargets: readonly [ThresholdEcdsaChainTarget];
    }
  | {
      kind: 'tempo_arc';
      sdkTargets: Extract<GoogleEmailOtpWalletAuthEcdsaTargets, { kind: 'explicit' }>;
      chainTargets: readonly [ThresholdEcdsaChainTarget, ThresholdEcdsaChainTarget];
    };

type IntendedPasskeyEcdsaTargetProfile =
  | { kind: 'none' }
  | { kind: 'tempo' }
  | { kind: 'tempo_arc' };

type IntendedEcdsaSignerProvisioningDefaults = ReturnType<
  typeof useSeams
>['seams']['configs']['signing']['thresholdEcdsa']['provisioningDefaults'];

type IntendedEcdsaSessionSummary =
  | {
      ecdsaTargetProfile: 'none';
      thresholdEcdsaEthereumAddress?: never;
      thresholdEcdsaPublicKeyB64u?: never;
    }
  | {
      ecdsaTargetProfile: 'tempo';
      thresholdEcdsaEthereumAddress: string;
      thresholdEcdsaPublicKeyB64u: string;
    }
  | {
      ecdsaTargetProfile: 'tempo_arc';
      thresholdEcdsaEthereumAddress?: never;
      thresholdEcdsaPublicKeyB64u?: never;
    };

type IntendedEcdsaSummary =
  | (Extract<IntendedEcdsaSessionSummary, { ecdsaTargetProfile: 'none' }> & {
      ecdsaTargetKeys: Extract<IntendedEcdsaTargetKeysSummary, { kind: 'none' }>;
    })
  | (Extract<IntendedEcdsaSessionSummary, { ecdsaTargetProfile: 'tempo' }> & {
      ecdsaTargetKeys: Extract<IntendedEcdsaTargetKeysSummary, { kind: 'tempo' }>;
    })
  | (Extract<IntendedEcdsaSessionSummary, { ecdsaTargetProfile: 'tempo_arc' }> & {
      ecdsaTargetKeys: Extract<IntendedEcdsaTargetKeysSummary, { kind: 'tempo_arc' }>;
    });

type IntendedActionSuccess = {
  status: 'success';
  action: IntendedActionName;
  result: IntendedActionResult;
  error?: never;
};

type IntendedActionError = {
  status: 'error';
  action: IntendedActionName;
  error: string;
  result?: never;
};

type IntendedActionState =
  | IntendedActionIdle
  | IntendedActionRunning
  | IntendedActionSuccess
  | IntendedActionError;

type PasskeyRegistrationCoreSummary = {
  kind: 'passkey_registration_success';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
} & IntendedEcdsaSessionSummary;

type PasskeyRegistrationResultSummary = PasskeyRegistrationCoreSummary & IntendedEcdsaSummary;

type Ed25519AddSignerResultSummary = {
  kind: 'near_ed25519_signer_added';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
};

type EmailOtpRegistrationCoreSummary = {
  kind: 'email_otp_registration_success';
  initialWalletId: string;
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
} & IntendedEcdsaSessionSummary;

type EmailOtpRegistrationResultSummary = EmailOtpRegistrationCoreSummary & IntendedEcdsaSummary;

type NearSigningResultSummary = {
  kind: 'near_sign_success';
  walletId: string;
  nearAccountId: string;
  signedTransactionB64: string;
  signedTransactionByteLength: number;
};

type PasskeyUnlockResultSummary = {
  kind: 'passkey_unlock_success';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
};

type EmailOtpUnlockCoreSummary = {
  kind: 'email_otp_unlock_success';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
} & IntendedEcdsaSessionSummary;

type EmailOtpUnlockResultSummary = EmailOtpUnlockCoreSummary & IntendedEcdsaSummary;

type TempoSigningResultSummary = {
  kind: 'tempo_sign_success';
  walletId: string;
  chainId: number;
  senderHashHex: `0x${string}`;
  rawTxHex: `0x${string}`;
};

type ArcEvmSigningResultSummary = {
  kind: 'arc_evm_sign_success';
  walletId: string;
  chainId: number;
  txHashHex: `0x${string}`;
  rawTxHex: `0x${string}`;
};

type EcdsaExportResultSummary = {
  kind: 'ecdsa_export_success';
  walletId: string;
  chainId: number;
};

type Ed25519ExportResultSummary = {
  kind: 'ed25519_export_success';
  walletId: string;
  nearAccountId: string;
};

type IntendedActionResult =
  | PasskeyRegistrationResultSummary
  | Ed25519AddSignerResultSummary
  | EmailOtpRegistrationResultSummary
  | NearSigningResultSummary
  | PasskeyUnlockResultSummary
  | EmailOtpUnlockResultSummary
  | TempoSigningResultSummary
  | ArcEvmSigningResultSummary
  | Ed25519ExportResultSummary
  | EcdsaExportResultSummary;

type IntendedPageState = {
  action: IntendedActionState;
  events: readonly IntendedLifecycleEvent[];
  walletId: string;
  nearAccountId: string | null;
  nearSignerSlot: number;
};

type IntendedPageAction =
  | {
      kind: 'action_started';
      action: IntendedActionName;
    }
  | {
      kind: 'action_succeeded';
      action: IntendedActionName;
      result: IntendedActionResult;
    }
  | {
      kind: 'action_failed';
      action: IntendedActionName;
      error: string;
    }
  | {
      kind: 'event_recorded';
      payload: unknown;
    };

type IntendedPageQuery = {
  flow: string;
  walletId: string;
  nearAccountId: string | null;
  nearSignerSlot: number;
  googleIdToken: string | null;
  passkeyEcdsaTargetProfile: IntendedPasskeyEcdsaTargetProfile;
  emailOtpEcdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
};

type IntendedPageControllerArgs = {
  walletId: string;
  nearAccountId: string | null;
  nearSignerSlot: number;
  googleIdToken: string | null;
  passkeyEcdsaTargetProfile: IntendedPasskeyEcdsaTargetProfile;
  emailOtpEcdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
  seams: ReturnType<typeof useSeams>['seams'];
  registerPasskey: ReturnType<typeof useSeams>['registerPasskey'];
  refreshLoginState: ReturnType<typeof useSeams>['refreshLoginState'];
  dispatch: React.Dispatch<IntendedPageAction>;
};

type IntendedEmailOtpCodeRequest =
  | {
      kind: 'challenge';
      challengeId: string;
      walletId: string;
    }
  | {
      kind: 'latest_for_wallet';
      walletId: string;
      challengeId?: never;
    };

type IntendedEmailOtpOutboxSuccess = {
  ok: true;
  otpCode: string;
};

declare global {
  interface Window {
    __seamsIntendedE2EReadEmailOtpCode?: (input: IntendedEmailOtpCodeRequest) => Promise<string>;
  }
}

const PENDING_ACTION_LABEL = 'Pending';
const INTENDED_TEMPO_CHAIN_ID = 42_431;
const INTENDED_ARC_EVM_CHAIN_ID = 5_042_002;
const INTENDED_TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: INTENDED_TEMPO_CHAIN_ID,
  networkSlug: 'tempo-testnet',
} satisfies ThresholdEcdsaChainTarget;
const INTENDED_ARC_EVM_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: INTENDED_ARC_EVM_CHAIN_ID,
  networkSlug: 'arc-testnet',
} satisfies ThresholdEcdsaChainTarget;
const INTENDED_EVM_RECIPIENT = '0x1111111111111111111111111111111111111111';
const INTENDED_TEMPO_RECIPIENT = '0x2222222222222222222222222222222222222222';
const INTENDED_MAX_PRIORITY_FEE_PER_GAS = 1n;
const INTENDED_MAX_FEE_PER_GAS = 1n;
const INTENDED_EVM_GAS_LIMIT = 21_000n;

function intendedRegistrationRpId() {
  const parsed = parseWebAuthnRpId(window.location.hostname);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

function intendedEd25519YaoSignerSelection(): RegistrationSignerSetSelection {
  return {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: {
          kind: 'implicit_account',
          accountIdSource: 'ed25519_public_key',
        },
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    ],
  };
}

function resolveIntendedActivationPoll(resolve: () => void): void {
  window.setTimeout(resolve, 25);
}

function waitForIntendedActivationPoll(): Promise<void> {
  return new Promise(resolveIntendedActivationPoll);
}

async function waitForIntendedRegistrationActivation(
  surface: WalletIframeRegistrationActivationSurface,
): Promise<RegistrationResult> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const state = surface.state();
    switch (state.kind) {
      case 'completed':
        return state.result;
      case 'cancelled':
        throw new Error(`Prepared iframe registration was cancelled: ${state.reason}`);
      case 'failed':
        throw new Error(state.error);
      case 'idle':
      case 'mounting':
      case 'ready':
      case 'starting':
        await waitForIntendedActivationPoll();
        break;
      default:
        assertNever(state);
    }
  }
  throw new Error('Prepared iframe registration timed out');
}

function intendedEcdsaChainTarget(
  chain: IntendedEcdsaTargetKeySummary['chain'],
): ThresholdEcdsaChainTarget {
  switch (chain) {
    case 'tempo':
      return INTENDED_TEMPO_CHAIN_TARGET;
    case 'arc_evm':
      return INTENDED_ARC_EVM_CHAIN_TARGET;
    default:
      return assertNever(chain);
  }
}

function initialIntendedPageState(query: IntendedPageQuery): IntendedPageState {
  return {
    action: { status: 'idle' },
    events: [],
    walletId: query.walletId,
    nearAccountId: query.nearAccountId,
    nearSignerSlot: query.nearSignerSlot,
  };
}

export const IntendedBehaviourE2EPage: React.FC = () => {
  const seamsContext = useSeams();
  const query = readIntendedPageQuery();
  const [state, dispatch] = React.useReducer(intendedPageReducer, query, initialIntendedPageState);
  const controller = new IntendedPageController({
    walletId: state.walletId,
    nearAccountId: state.nearAccountId,
    nearSignerSlot: state.nearSignerSlot,
    googleIdToken: query.googleIdToken,
    passkeyEcdsaTargetProfile: query.passkeyEcdsaTargetProfile,
    emailOtpEcdsaTargetProfile: query.emailOtpEcdsaTargetProfile,
    seams: seamsContext.seams,
    registerPasskey: seamsContext.registerPasskey,
    refreshLoginState: seamsContext.refreshLoginState,
    dispatch,
  });
  const snapshot = JSON.stringify(state, null, 2);
  const action = actionNameFromState(state.action);
  installIntendedE2EHelpers(controller);

  return (
    <main
      data-testid="intended-e2e-page"
      data-flow={query.flow}
      data-wallet-id={state.walletId}
      data-login-state={seamsContext.loginState.isLoggedIn ? 'logged_in' : 'logged_out'}
      data-login-wallet-id={seamsContext.loginState.walletId || ''}
      style={pageStyle}
    >
      <section style={panelStyle}>
        <h1 style={headingStyle}>Intended Behaviour E2E</h1>
        <dl style={definitionListStyle}>
          <dt>Flow</dt>
          <dd>{query.flow}</dd>
          <dt>Wallet</dt>
          <dd>{state.walletId}</dd>
          <dt>NEAR</dt>
          <dd>{state.nearAccountId || 'none'}</dd>
        </dl>
        <div style={buttonRowStyle}>
          <button
            type="button"
            data-testid="intended-register-passkey"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterPasskeyWallet}
            style={buttonStyle}
          >
            Register Passkey
          </button>
          <button
            type="button"
            data-testid="intended-register-passkey-ed25519-yao"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterPasskeyEd25519YaoWallet}
            style={buttonStyle}
          >
            Register Passkey Ed25519 Yao
          </button>
          <button
            type="button"
            data-testid="intended-register-prepared-iframe-passkey-ed25519-yao"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterPreparedIframePasskeyEd25519YaoWallet}
            style={buttonStyle}
          >
            Prepare Iframe Passkey Ed25519 Yao
          </button>
          <div
            data-testid="intended-prepared-iframe-registration-target"
            style={registrationActivationTargetStyle}
          />
          <button
            type="button"
            data-testid="intended-add-passkey-ed25519-yao-signer"
            disabled={state.action.status === 'running'}
            onClick={controller.runAddPasskeyEd25519YaoWalletSigner}
            style={buttonStyle}
          >
            Add Passkey Ed25519 Yao Signer
          </button>
          <button
            type="button"
            data-testid="intended-register-email-otp"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterEmailOtpWallet}
            style={buttonStyle}
          >
            Register Email OTP
          </button>
          <button
            type="button"
            data-testid="intended-sign-near"
            disabled={state.action.status === 'running'}
            onClick={controller.runSignNearTransaction}
            style={buttonStyle}
          >
            Sign NEAR
          </button>
          <button
            type="button"
            data-testid="intended-unlock-passkey"
            disabled={state.action.status === 'running'}
            onClick={controller.runUnlockPasskeyWallet}
            style={buttonStyle}
          >
            Unlock Passkey
          </button>
          <button
            type="button"
            data-testid="intended-unlock-email-otp"
            disabled={state.action.status === 'running'}
            onClick={controller.runUnlockEmailOtpWallet}
            style={buttonStyle}
          >
            Unlock Email OTP
          </button>
          <button
            type="button"
            data-testid="intended-sign-tempo"
            disabled={state.action.status === 'running'}
            onClick={controller.runSignTempoTransaction}
            style={buttonStyle}
          >
            Sign Tempo
          </button>
          <button
            type="button"
            data-testid="intended-sign-arc-evm"
            disabled={state.action.status === 'running'}
            onClick={controller.runSignArcEvmTransaction}
            style={buttonStyle}
          >
            Sign Arc
          </button>
          <button
            type="button"
            data-testid="intended-export-ed25519"
            disabled={state.action.status === 'running'}
            onClick={controller.runExportEd25519Key}
            style={buttonStyle}
          >
            Export Ed25519
          </button>
          <button
            type="button"
            data-testid="intended-export-ecdsa"
            disabled={state.action.status === 'running'}
            onClick={controller.runExportEcdsaKey}
            style={buttonStyle}
          >
            Export ECDSA
          </button>
        </div>
        <output
          data-testid="intended-action-status"
          data-state={state.action.status}
          data-action={action}
          style={statusStyle}
        >
          {state.action.status === 'idle' ? PENDING_ACTION_LABEL : state.action.status}
        </output>
        <pre data-testid="intended-result-json" style={snapshotStyle}>
          {snapshot}
        </pre>
      </section>
    </main>
  );
};

class IntendedPageController {
  private walletId: string;

  private nearAccountId: string | null;

  private readonly nearSignerSlot: number;

  private readonly googleIdToken: string | null;

  private readonly passkeyEcdsaTargetProfile: IntendedPasskeyEcdsaTargetProfile;

  private readonly emailOtpEcdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;

  private readonly seams: ReturnType<typeof useSeams>['seams'];

  private readonly registerPasskey: ReturnType<typeof useSeams>['registerPasskey'];

  private readonly refreshLoginState: ReturnType<typeof useSeams>['refreshLoginState'];

  private readonly dispatch: React.Dispatch<IntendedPageAction>;

  constructor(args: IntendedPageControllerArgs) {
    this.walletId = args.walletId;
    this.nearAccountId = args.nearAccountId;
    this.nearSignerSlot = args.nearSignerSlot;
    this.googleIdToken = args.googleIdToken;
    this.passkeyEcdsaTargetProfile = args.passkeyEcdsaTargetProfile;
    this.emailOtpEcdsaTargetProfile = args.emailOtpEcdsaTargetProfile;
    this.seams = args.seams;
    this.registerPasskey = args.registerPasskey;
    this.refreshLoginState = args.refreshLoginState;
    this.dispatch = args.dispatch;
  }

  runRegisterPasskeyWallet = (): void => {
    void this.registerPasskeyWallet();
  };

  runRegisterPasskeyEd25519YaoWallet = (): void => {
    void this.registerPasskeyEd25519YaoWallet();
  };

  runRegisterPreparedIframePasskeyEd25519YaoWallet = (): void => {
    void this.registerPreparedIframePasskeyEd25519YaoWallet();
  };

  runAddPasskeyEd25519YaoWalletSigner = (): void => {
    void this.addPasskeyEd25519YaoWalletSigner();
  };

  runRegisterEmailOtpWallet = (): void => {
    void this.registerEmailOtpWallet();
  };

  runSignNearTransaction = (): void => {
    void this.signNearTransaction();
  };

  runUnlockPasskeyWallet = (): void => {
    void this.unlockPasskeyWallet();
  };

  runUnlockEmailOtpWallet = (): void => {
    void this.unlockEmailOtpWallet();
  };

  runSignTempoTransaction = (): void => {
    void this.signTempoTransaction();
  };

  runSignArcEvmTransaction = (): void => {
    void this.signArcEvmTransaction();
  };

  runExportEcdsaKey = (): void => {
    void this.exportEcdsaKey();
  };

  runExportEd25519Key = (): void => {
    void this.exportEd25519Key();
  };

  private async registerPasskeyWallet(): Promise<void> {
    const action: IntendedActionName = 'registerPasskeyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const result = await this.registerPasskey({
        wallet: {
          kind: 'provided',
          walletId: toWalletId(this.walletId),
        },
        signerOptions: passkeySignerOptionsForProfile({
          defaults: this.seams.configs.signing.thresholdEcdsa.provisioningDefaults,
          profile: this.passkeyEcdsaTargetProfile,
        }),
        onEvent: this.recordLifecycleEvent,
      });
      const registration = assertPasskeyRegistrationSucceeded({
        result,
        expectedWalletId: this.walletId,
        ecdsaTargetProfile: this.passkeyEcdsaTargetProfile,
      });
      await this.refreshLoginState(registration.walletId);
      const ecdsaTargetKeys = await this.readEcdsaTargetKeys(this.passkeyEcdsaTargetProfile.kind);
      const ecdsa = assertEcdsaTargetKeysForSession({
        session: registration,
        ecdsaTargetKeys,
      });
      const summary: PasskeyRegistrationResultSummary = {
        kind: registration.kind,
        walletId: registration.walletId,
        nearAccountId: registration.nearAccountId,
        nearEd25519SigningKeyId: registration.nearEd25519SigningKeyId,
        operationalPublicKey: registration.operationalPublicKey,
        ...ecdsa,
      };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async registerPasskeyEd25519YaoWallet(): Promise<void> {
    const action: IntendedActionName = 'registerPasskeyEd25519YaoWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const result = await this.seams.registration.registerWallet({
        authMethod: {
          kind: 'passkey',
          rpId: intendedRegistrationRpId(),
        },
        wallet: {
          kind: 'provided',
          walletId: toWalletId(this.walletId),
        },
        signerSelection: intendedEd25519YaoSignerSelection(),
        options: {
          onEvent: this.recordLifecycleEvent,
        },
      });
      const registration = assertPasskeyRegistrationSucceeded({
        result,
        expectedWalletId: this.walletId,
        ecdsaTargetProfile: { kind: 'none' },
      });
      await this.refreshLoginState(registration.walletId);
      const summary: PasskeyRegistrationResultSummary = {
        kind: registration.kind,
        walletId: registration.walletId,
        nearAccountId: registration.nearAccountId,
        nearEd25519SigningKeyId: registration.nearEd25519SigningKeyId,
        operationalPublicKey: registration.operationalPublicKey,
        ecdsaTargetProfile: 'none',
        ecdsaTargetKeys: { kind: 'none' },
      };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async registerPreparedIframePasskeyEd25519YaoWallet(): Promise<void> {
    const action: IntendedActionName = 'registerPreparedIframePasskeyEd25519YaoWallet';
    this.dispatch({ kind: 'action_started', action });
    const target = document.querySelector<HTMLElement>(
      '[data-testid="intended-prepared-iframe-registration-target"]',
    );
    if (!target) {
      this.dispatch({
        kind: 'action_failed',
        action,
        error: 'Prepared iframe registration target is unavailable',
      });
      return;
    }
    const surface = this.seams.registration.createPasskeyRegistrationActivationSurface({
      wallet: {
        kind: 'provided',
        walletId: toWalletId(this.walletId),
      },
      signerSelection: intendedEd25519YaoSignerSelection(),
      options: {
        onEvent: this.recordLifecycleEvent,
      },
      presentation: {
        kind: 'outline_overlay',
        label: 'Create Ed25519 wallet',
        busyLabel: 'Creating Ed25519 wallet...',
        accessibleLabel: 'Create Ed25519 wallet with passkey',
      },
    });
    try {
      surface.mount(target);
      const result = await waitForIntendedRegistrationActivation(surface);
      const registration = assertPasskeyRegistrationSucceeded({
        result,
        expectedWalletId: this.walletId,
        ecdsaTargetProfile: { kind: 'none' },
      });
      await this.refreshLoginState(registration.walletId);
      const summary: PasskeyRegistrationResultSummary = {
        kind: registration.kind,
        walletId: registration.walletId,
        nearAccountId: registration.nearAccountId,
        nearEd25519SigningKeyId: registration.nearEd25519SigningKeyId,
        operationalPublicKey: registration.operationalPublicKey,
        ecdsaTargetProfile: 'none',
        ecdsaTargetKeys: { kind: 'none' },
      };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    } finally {
      surface.dispose();
    }
  }

  private async addPasskeyEd25519YaoWalletSigner(): Promise<void> {
    const action: IntendedActionName = 'addPasskeyEd25519YaoWalletSigner';
    this.dispatch({ kind: 'action_started', action });
    try {
      const result = await this.seams.registration.addWalletSigner({
        walletId: toWalletId(this.walletId),
        rpId: intendedRegistrationRpId(),
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_implicit_near_account',
            signerSlot: 2,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'router-ab-ed25519-yao-v1',
            derivationVersion: 1,
          },
        },
        options: {
          onEvent: this.recordLifecycleEvent,
        },
      });
      const summary = assertEd25519AddSignerSucceeded(result, this.walletId);
      this.nearAccountId = summary.nearAccountId;
      await this.refreshLoginState(summary.walletId);
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async registerEmailOtpWallet(): Promise<void> {
    const action: IntendedActionName = 'registerEmailOtpWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const registration = await this.registerEmailOtpWalletWithPublicSdk();
      this.walletId = registration.walletId;
      this.nearAccountId = registration.nearAccountId;
      await this.refreshLoginState(this.walletId);
      const ecdsaTargetKeys = await this.readEcdsaTargetKeys(this.emailOtpEcdsaTargetProfile.kind);
      const ecdsa = assertEcdsaTargetKeysForSession({
        session: registration,
        ecdsaTargetKeys,
      });
      const summary: EmailOtpRegistrationResultSummary = {
        kind: registration.kind,
        initialWalletId: registration.initialWalletId,
        walletId: registration.walletId,
        nearAccountId: registration.nearAccountId,
        operationalPublicKey: registration.operationalPublicKey,
        signingSessionStatus: registration.signingSessionStatus,
        remainingUses: registration.remainingUses,
        ...ecdsa,
      };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async signNearTransaction(): Promise<void> {
    const action: IntendedActionName = 'signNearTransaction';
    this.dispatch({ kind: 'action_started', action });
    try {
      const summary = await this.signNearTransactionWithPublicSdk();
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async unlockPasskeyWallet(): Promise<void> {
    const action: IntendedActionName = 'unlockPasskeyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      await this.seams.auth.lock();
      const result = await this.seams.auth.unlock(this.walletId, {
        onEvent: this.recordLifecycleEvent,
      });
      const summary = assertPasskeyUnlockSucceeded(result, this.walletId);
      await this.refreshLoginState(summary.walletId);
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async unlockEmailOtpWallet(): Promise<void> {
    const action: IntendedActionName = 'unlockEmailOtpWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      await this.seams.auth.lock();
      const unlock = await this.unlockEmailOtpWalletWithPublicSdk();
      await this.refreshLoginState(unlock.walletId);
      const ecdsaTargetKeys = await this.readEcdsaTargetKeys(this.emailOtpEcdsaTargetProfile.kind);
      const ecdsa = assertEcdsaTargetKeysForSession({
        session: unlock,
        ecdsaTargetKeys,
      });
      const summary: EmailOtpUnlockResultSummary = {
        kind: unlock.kind,
        walletId: unlock.walletId,
        nearAccountId: unlock.nearAccountId,
        operationalPublicKey: unlock.operationalPublicKey,
        signingSessionStatus: unlock.signingSessionStatus,
        remainingUses: unlock.remainingUses,
        ...ecdsa,
      };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async signTempoTransaction(): Promise<void> {
    const action: IntendedActionName = 'signTempoTransaction';
    this.dispatch({ kind: 'action_started', action });
    try {
      const summary = await this.signTempoTransactionWithPublicSdk();
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async signArcEvmTransaction(): Promise<void> {
    const action: IntendedActionName = 'signArcEvmTransaction';
    this.dispatch({ kind: 'action_started', action });
    try {
      const summary = await this.signArcEvmTransactionWithPublicSdk();
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async exportEcdsaKey(): Promise<void> {
    const action: IntendedActionName = 'exportEcdsaKey';
    this.dispatch({ kind: 'action_started', action });
    try {
      const summary = await this.exportEcdsaKeyWithPublicSdk();
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async exportEd25519Key(): Promise<void> {
    const action: IntendedActionName = 'exportEd25519Key';
    this.dispatch({ kind: 'action_started', action });
    try {
      const summary = await this.exportEd25519KeyWithPublicSdk();
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async readEcdsaTargetKeys(
    profile: IntendedEcdsaTargetProfileName,
  ): Promise<IntendedEcdsaTargetKeysSummary> {
    const walletSession = walletSessionRefFromSession({
      walletId: this.walletId,
      walletSessionUserId: this.walletId,
    });
    switch (profile) {
      case 'none':
        return { kind: 'none' };
      case 'tempo': {
        const tempo = await this.resolveEcdsaTargetKey({
          chain: 'tempo',
          walletSession,
        });
        return { kind: 'tempo', tempo };
      }
      case 'tempo_arc': {
        const tempo = await this.resolveEcdsaTargetKey({
          chain: 'tempo',
          walletSession,
        });
        const arcEvm = await this.resolveEcdsaTargetKey({
          chain: 'arc_evm',
          walletSession,
        });
        return { kind: 'tempo_arc', tempo, arcEvm };
      }
      default:
        return assertNever(profile);
    }
  }

  private async resolveEcdsaTargetKey(input: {
    chain: 'tempo' | 'arc_evm';
    walletSession: ReturnType<typeof walletSessionRefFromSession>;
  }): Promise<IntendedEcdsaTargetKeySummary> {
    const chainTarget = intendedEcdsaChainTarget(input.chain);
    const resolved = await this.seams.keys.resolveExactKeyExportLane({
      kind: 'ecdsa',
      walletSession: input.walletSession,
      chainTarget,
    });
    if (resolved.kind !== 'ecdsa') {
      throw new Error(`ECDSA target key returned unexpected kind: ${resolved.kind}`);
    }
    return {
      chain: input.chain,
      chainId: chainTarget.chainId,
      thresholdOwnerAddress: requireNonEmptyString(
        resolved.laneIdentity.signer.key.thresholdOwnerAddress,
        `${input.chain} thresholdOwnerAddress`,
      ),
    };
  }

  private async signNearTransactionWithPublicSdk(): Promise<NearSigningResultSummary> {
    const nearAccountId = requireNearAccountId(this.nearAccountId);
    const result = await this.seams.near.signTransactionWithActions({
      walletSession: walletSessionRefFromSession({
        walletId: this.walletId,
        walletSessionUserId: this.walletId,
      }),
      nearAccount: nearAccountRefFromAccountId(nearAccountId),
      transaction: {
        receiverId: nearAccountId,
        actions: [
          {
            type: ActionType.Transfer,
            amount: '0',
          },
        ],
      },
      options: {
        signerSlot: this.nearSignerSlot,
        onEvent: this.recordLifecycleEvent,
      },
    });
    const signedTransactionB64 = encodeSignedTransactionBase64(result.signedTransaction);
    const signedTransactionByteLength = normalizeSignedTransactionByteLength(
      result.signedTransaction,
    );
    if (result.nearAccountId !== nearAccountId) {
      throw new Error(`NEAR signing account mismatch: ${result.nearAccountId}`);
    }
    if (!signedTransactionB64 || signedTransactionByteLength <= 0) {
      throw new Error('NEAR signing did not return signed transaction bytes');
    }
    return {
      kind: 'near_sign_success',
      walletId: this.walletId,
      nearAccountId,
      signedTransactionB64,
      signedTransactionByteLength,
    };
  }

  private async registerEmailOtpWalletWithPublicSdk(): Promise<EmailOtpRegistrationCoreSummary> {
    const idToken = requireGoogleIdToken(this.googleIdToken);
    const flowResult = await this.seams.auth.beginGoogleEmailOtpWalletAuth({
      idToken,
      mode: 'register',
      sessionKind: 'jwt',
      ecdsaTargets: this.emailOtpEcdsaTargetProfile.sdkTargets,
      emailOtpAuthPolicy: 'session',
      onEvent: this.recordLifecycleEvent,
    });
    if (!flowResult.ok) {
      throw new Error(flowResult.error.message);
    }
    if (flowResult.value.mode !== 'register') {
      throw new Error(`Email OTP registration resolved unexpected mode: ${flowResult.value.mode}`);
    }
    const initialWalletId = flowResult.value.walletId;
    const rerollResult = await flowResult.value.rerollWalletId();
    if (!rerollResult.ok) {
      throw new Error(rerollResult.error.message);
    }
    const registrationFlow = rerollResult.value;
    const completed = await registrationFlow.completeRegistration();
    if (!completed.ok) {
      throw new Error(completed.error.message);
    }
    return assertEmailOtpRegistrationCompleted({
      completed: completed.value,
      initialWalletId,
      ecdsaTargetProfile: this.emailOtpEcdsaTargetProfile,
    });
  }

  private async unlockEmailOtpWalletWithPublicSdk(): Promise<EmailOtpUnlockCoreSummary> {
    const idToken = requireGoogleIdToken(this.googleIdToken);
    const flowResult = await this.seams.auth.beginGoogleEmailOtpWalletAuth({
      idToken,
      mode: 'login',
      sessionKind: 'jwt',
      ecdsaTargets: this.emailOtpEcdsaTargetProfile.sdkTargets,
      emailOtpAuthPolicy: 'session',
      onEvent: this.recordLifecycleEvent,
    });
    if (!flowResult.ok) {
      throw new Error(flowResult.error.message);
    }
    if (flowResult.value.mode !== 'login') {
      throw new Error(`Email OTP unlock resolved unexpected mode: ${flowResult.value.mode}`);
    }
    if (flowResult.value.walletId !== this.walletId) {
      throw new Error(`Email OTP unlock wallet mismatch: ${flowResult.value.walletId}`);
    }
    const challengeId = googleEmailOtpLoginFlowChallengeId({
      flowId: flowResult.value.flowId,
      walletId: this.walletId,
    });
    const otpCode = await this.readEmailOtpCodeForChallenge({
      kind: 'challenge',
      challengeId,
      walletId: this.walletId,
    });
    const submitted = await flowResult.value.submit({ otpCode });
    if (!submitted.ok) {
      throw new Error(submitted.error.message);
    }
    return assertEmailOtpUnlockSucceeded({
      result: submitted.value,
      expectedWalletId: this.walletId,
      ecdsaTargetProfile: this.emailOtpEcdsaTargetProfile,
    });
  }

  readEmailOtpCodeForChallenge = async (input: IntendedEmailOtpCodeRequest): Promise<string> => {
    const lookup = parseEmailOtpCodeLookup(input);
    const walletId = requireWalletIdString(input.walletId);
    const idToken = requireGoogleIdToken(this.googleIdToken);
    const exchange = await this.seams.auth.exchangeGoogleEmailOtpSession({
      idToken,
      accountMode: 'login',
      sessionKind: 'jwt',
      onEvent: this.recordLifecycleEvent,
    });
    const exchangeWalletId = String(exchange.session.walletId || '').trim();
    if (exchangeWalletId !== walletId) {
      throw new Error(`Email OTP outbox app-session wallet mismatch: ${exchangeWalletId}`);
    }
    const appSessionJwt = String(exchange.jwt || '').trim();
    if (!appSessionJwt) {
      throw new Error('Email OTP dev outbox requires an app-session JWT');
    }
    const url = emailOtpDevOutboxUrl({
      relayerUrl: requireRelayerUrl(this.seams.configs.network.relayer?.url),
      walletId,
      lookup,
    });
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${appSessionJwt}`,
      },
    });
    const json = await response.json();
    const outbox = parseEmailOtpOutboxSuccess(json);
    return outbox.otpCode;
  };

  private async signTempoTransactionWithPublicSdk(): Promise<TempoSigningResultSummary> {
    const result = await this.seams.tempo.signTempo({
      walletSession: walletSessionRefFromSession({
        walletId: this.walletId,
        walletSessionUserId: this.walletId,
      }),
      chainTarget: INTENDED_TEMPO_CHAIN_TARGET,
      request: buildIntendedTempoSigningRequest(),
      options: {
        onEvent: this.recordLifecycleEvent,
      },
    });
    if (result.chain !== 'tempo' || result.kind !== 'tempoTransaction') {
      throw new Error(`Tempo signing returned unexpected result: ${result.chain}/${result.kind}`);
    }
    return {
      kind: 'tempo_sign_success',
      walletId: this.walletId,
      chainId: INTENDED_TEMPO_CHAIN_ID,
      senderHashHex: requireHex(result.senderHashHex, 'Tempo senderHashHex'),
      rawTxHex: requireHex(result.rawTxHex, 'Tempo rawTxHex'),
    };
  }

  private async signArcEvmTransactionWithPublicSdk(): Promise<ArcEvmSigningResultSummary> {
    const result = await this.seams.tempo.signTempo({
      walletSession: walletSessionRefFromSession({
        walletId: this.walletId,
        walletSessionUserId: this.walletId,
      }),
      chainTarget: INTENDED_ARC_EVM_CHAIN_TARGET,
      request: buildIntendedArcEvmSigningRequest(),
      options: {
        onEvent: this.recordLifecycleEvent,
      },
    });
    if (result.chain !== 'evm' || result.kind !== 'eip1559') {
      throw new Error(`Arc/EVM signing returned unexpected result: ${result.chain}/${result.kind}`);
    }
    return {
      kind: 'arc_evm_sign_success',
      walletId: this.walletId,
      chainId: INTENDED_ARC_EVM_CHAIN_ID,
      txHashHex: requireHex(result.txHashHex, 'Arc/EVM txHashHex'),
      rawTxHex: requireHex(result.rawTxHex, 'Arc/EVM rawTxHex'),
    };
  }

  private async exportEcdsaKeyWithPublicSdk(): Promise<EcdsaExportResultSummary> {
    const walletSession = walletSessionRefFromSession({
      walletId: this.walletId,
      walletSessionUserId: this.walletId,
    });
    const chainTarget = INTENDED_ARC_EVM_CHAIN_TARGET;
    const resolvedLane = await this.seams.keys.resolveExactKeyExportLane({
      kind: 'ecdsa',
      walletSession,
      chainTarget,
    });
    if (resolvedLane.kind !== 'ecdsa') {
      throw new Error(`ECDSA export lane returned unexpected kind: ${resolvedLane.kind}`);
    }
    await this.seams.keys.exportKeypairWithUI({
      kind: 'ecdsa',
      walletSession,
      chainTarget,
      laneIdentity: resolvedLane.laneIdentity,
      options: {
        variant: 'drawer',
        onEvent: this.recordLifecycleEvent,
      },
    });
    return {
      kind: 'ecdsa_export_success',
      walletId: this.walletId,
      chainId: chainTarget.chainId,
    };
  }

  private async exportEd25519KeyWithPublicSdk(): Promise<Ed25519ExportResultSummary> {
    const nearAccountId = requireNearAccountId(this.nearAccountId);
    const walletSession = walletSessionRefFromSession({
      walletId: this.walletId,
      walletSessionUserId: this.walletId,
    });
    const nearAccount = nearAccountRefFromAccountId(nearAccountId);
    const resolvedLane = await this.seams.keys.resolveExactKeyExportLane({
      kind: 'ed25519',
      walletSession,
      nearAccount,
    });
    if (resolvedLane.kind !== 'ed25519') {
      throw new Error(`Ed25519 export lane returned unexpected kind: ${resolvedLane.kind}`);
    }
    await this.seams.keys.exportKeypairWithUI({
      kind: 'ed25519',
      walletSession,
      nearAccount,
      laneIdentity: resolvedLane.laneIdentity,
      options: {
        variant: 'drawer',
        onEvent: this.recordLifecycleEvent,
      },
    });
    return {
      kind: 'ed25519_export_success',
      walletId: this.walletId,
      nearAccountId,
    };
  }

  private recordLifecycleEvent = (event: unknown): void => {
    this.dispatch({ kind: 'event_recorded', payload: jsonSafeValue(event) });
  };
}

function buildIntendedTempoSigningRequest() {
  return {
    chain: 'tempo' as const,
    kind: 'tempoTransaction' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: INTENDED_TEMPO_CHAIN_ID,
      maxPriorityFeePerGas: INTENDED_MAX_PRIORITY_FEE_PER_GAS,
      maxFeePerGas: INTENDED_MAX_FEE_PER_GAS,
      gasLimit: INTENDED_EVM_GAS_LIMIT,
      calls: [
        {
          to: INTENDED_TEMPO_RECIPIENT,
          value: 0n,
          input: '0x' as const,
        },
      ],
      accessList: [],
      nonceKey: 0n,
      validBefore: null,
      validAfter: null,
      feePayerSignature: { kind: 'none' as const },
      aaAuthorizationList: [],
    },
  };
}

function buildIntendedArcEvmSigningRequest() {
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: INTENDED_ARC_EVM_CHAIN_ID,
      maxPriorityFeePerGas: INTENDED_MAX_PRIORITY_FEE_PER_GAS,
      maxFeePerGas: INTENDED_MAX_FEE_PER_GAS,
      gasLimit: INTENDED_EVM_GAS_LIMIT,
      to: INTENDED_EVM_RECIPIENT,
      value: 0n,
      data: '0x' as const,
      accessList: [],
    },
  };
}

function intendedPageReducer(
  state: IntendedPageState,
  action: IntendedPageAction,
): IntendedPageState {
  switch (action.kind) {
    case 'action_started':
      return {
        ...state,
        action: { status: 'running', action: action.action },
        events: [],
      };
    case 'action_succeeded':
      return {
        ...state,
        action: { status: 'success', action: action.action, result: action.result },
        walletId: intendedActionResultWalletId(action.result) || state.walletId,
        nearAccountId: intendedActionResultNearAccountId(action.result) || state.nearAccountId,
        nearSignerSlot: intendedActionResultNearSignerSlot(action.result, state.nearSignerSlot),
      };
    case 'action_failed':
      return {
        ...state,
        action: { status: 'error', action: action.action, error: action.error },
      };
    case 'event_recorded':
      return {
        ...state,
        events: [
          ...state.events,
          {
            index: state.events.length,
            payload: action.payload,
          },
        ],
      };
    default:
      return assertNever(action);
  }
}

function intendedActionResultWalletId(result: IntendedActionResult): string | null {
  switch (result.kind) {
    case 'passkey_registration_success':
    case 'near_ed25519_signer_added':
    case 'email_otp_registration_success':
    case 'near_sign_success':
    case 'passkey_unlock_success':
    case 'email_otp_unlock_success':
    case 'tempo_sign_success':
    case 'arc_evm_sign_success':
    case 'ed25519_export_success':
    case 'ecdsa_export_success':
      return result.walletId;
    default:
      return assertNever(result);
  }
}

function intendedActionResultNearAccountId(result: IntendedActionResult): string | null {
  switch (result.kind) {
    case 'passkey_registration_success':
    case 'near_ed25519_signer_added':
    case 'email_otp_registration_success':
    case 'near_sign_success':
    case 'passkey_unlock_success':
    case 'email_otp_unlock_success':
    case 'ed25519_export_success':
      return result.nearAccountId;
    case 'tempo_sign_success':
    case 'arc_evm_sign_success':
    case 'ecdsa_export_success':
      return null;
    default:
      return assertNever(result);
  }
}

function intendedActionResultNearSignerSlot(
  result: IntendedActionResult,
  currentSignerSlot: number,
): number {
  switch (result.kind) {
    case 'passkey_registration_success':
    case 'email_otp_registration_success':
      return 1;
    case 'near_ed25519_signer_added':
      return 2;
    case 'near_sign_success':
    case 'passkey_unlock_success':
    case 'email_otp_unlock_success':
    case 'tempo_sign_success':
    case 'arc_evm_sign_success':
    case 'ed25519_export_success':
    case 'ecdsa_export_success':
      return currentSignerSlot;
    default:
      return assertNever(result);
  }
}

function readIntendedPageQuery(): IntendedPageQuery {
  if (typeof window === 'undefined') {
    return {
      flow: 'unknown',
      walletId: 'unknown-wallet',
      nearAccountId: null,
      nearSignerSlot: 1,
      googleIdToken: null,
      passkeyEcdsaTargetProfile: defaultPasskeyEcdsaTargetProfile(),
      emailOtpEcdsaTargetProfile: defaultEmailOtpEcdsaTargetProfile(),
    };
  }
  const params = new URLSearchParams(window.location.search);
  return {
    flow: stringParam(params, 'flow', 'unknown'),
    walletId: stringParam(params, 'walletId', 'unknown-wallet'),
    nearAccountId: optionalStringParam(params, 'nearAccountId'),
    nearSignerSlot: signerSlotParam(params),
    googleIdToken: optionalStringParam(params, 'googleIdToken'),
    passkeyEcdsaTargetProfile: passkeyEcdsaTargetProfileFromQuery(params),
    emailOtpEcdsaTargetProfile: emailOtpEcdsaTargetProfileFromQuery(params),
  };
}

function signerSlotParam(params: URLSearchParams): number {
  const raw = params.get('nearSignerSlot');
  if (raw === null) return 1;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error('nearSignerSlot must be a positive safe integer');
  }
  return parsed;
}

function defaultPasskeyEcdsaTargetProfile(): IntendedPasskeyEcdsaTargetProfile {
  return { kind: 'tempo_arc' };
}

function defaultEmailOtpEcdsaTargetProfile(): IntendedEmailOtpEcdsaTargetProfile {
  return {
    kind: 'tempo_arc',
    sdkTargets: {
      kind: 'explicit',
      targets: [INTENDED_TEMPO_CHAIN_TARGET, INTENDED_ARC_EVM_CHAIN_TARGET],
    },
    chainTargets: [INTENDED_TEMPO_CHAIN_TARGET, INTENDED_ARC_EVM_CHAIN_TARGET],
  };
}

function passkeyEcdsaTargetProfileFromQuery(
  params: URLSearchParams,
): IntendedPasskeyEcdsaTargetProfile {
  const name = stringParam(params, 'passkeyEcdsaTargetProfile', 'tempo_arc');
  const profile = parseEcdsaTargetProfileName(name, 'passkeyEcdsaTargetProfile');
  switch (profile) {
    case 'none':
      return { kind: 'none' };
    case 'tempo':
      return { kind: 'tempo' };
    case 'tempo_arc':
      return { kind: 'tempo_arc' };
    default:
      return assertNever(profile);
  }
}

function emailOtpEcdsaTargetProfileFromQuery(
  params: URLSearchParams,
): IntendedEmailOtpEcdsaTargetProfile {
  const name = stringParam(params, 'emailOtpEcdsaTargetProfile', 'tempo_arc');
  const profile = parseEcdsaTargetProfileName(name, 'emailOtpEcdsaTargetProfile');
  switch (profile) {
    case 'none':
      return {
        kind: 'none',
        sdkTargets: { kind: 'none' },
        chainTargets: [],
      };
    case 'tempo':
      return {
        kind: 'tempo',
        sdkTargets: {
          kind: 'explicit',
          targets: [INTENDED_TEMPO_CHAIN_TARGET],
        },
        chainTargets: [INTENDED_TEMPO_CHAIN_TARGET],
      };
    case 'tempo_arc':
      return defaultEmailOtpEcdsaTargetProfile();
    default:
      return assertNever(profile);
  }
}

function parseEcdsaTargetProfileName(value: string, label: string): IntendedEcdsaTargetProfileName {
  switch (value) {
    case 'none':
    case 'tempo':
    case 'tempo_arc':
      return value;
    default:
      throw new Error(`Unknown ${label}: ${value}`);
  }
}

function passkeySignerOptionsForProfile(args: {
  defaults: IntendedEcdsaSignerProvisioningDefaults;
  profile: IntendedPasskeyEcdsaTargetProfile;
}): IntendedEcdsaSignerProvisioningDefaults {
  switch (args.profile.kind) {
    case 'none':
      return {
        tempo: {
          ...args.defaults.tempo,
          enabled: false,
        },
        evm: {
          ...args.defaults.evm,
          enabled: false,
        },
      };
    case 'tempo':
      return {
        tempo: {
          ...args.defaults.tempo,
          enabled: true,
        },
        evm: {
          ...args.defaults.evm,
          enabled: false,
        },
      };
    case 'tempo_arc':
      return {
        tempo: {
          ...args.defaults.tempo,
          enabled: true,
        },
        evm: {
          ...args.defaults.evm,
          enabled: true,
        },
      };
    default:
      return assertNever(args.profile);
  }
}

function stringParam(params: URLSearchParams, key: string, fallback: string): string {
  const value = String(params.get(key) ?? '').trim();
  return value || fallback;
}

function optionalStringParam(params: URLSearchParams, key: string): string | null {
  const value = String(params.get(key) ?? '').trim();
  return value || null;
}

function actionNameFromState(state: IntendedActionState): string {
  switch (state.status) {
    case 'idle':
      return 'none';
    case 'running':
    case 'success':
    case 'error':
      return state.action;
    default:
      return assertNever(state);
  }
}

function assertPasskeyRegistrationSucceeded(args: {
  result: RegistrationResult;
  expectedWalletId: string;
  ecdsaTargetProfile: IntendedPasskeyEcdsaTargetProfile;
}): PasskeyRegistrationCoreSummary {
  const result = args.result;
  if (!result.success) {
    throw new Error(result.error || 'Passkey registration failed');
  }
  switch (args.ecdsaTargetProfile.kind) {
    case 'none': {
      if (result.kind !== 'near_wallet_registered') {
        throw new Error(`NEAR-only passkey registration returned result kind: ${result.kind}`);
      }
      return {
        ...passkeyRegistrationIdentitySummary({
          result,
          expectedWalletId: args.expectedWalletId,
        }),
        ecdsaTargetProfile: 'none',
      };
    }
    case 'tempo': {
      if (result.kind !== 'near_ed25519_and_ecdsa_wallet_registered') {
        throw new Error(`Mixed passkey registration returned result kind: ${result.kind}`);
      }
      const ecdsa = requireThresholdEcdsaSessionFields({
        source: result,
        label: 'Passkey registration',
      });
      return {
        ...passkeyRegistrationIdentitySummary({
          result,
          expectedWalletId: args.expectedWalletId,
        }),
        ...ecdsa,
      };
    }
    case 'tempo_arc': {
      if (result.kind !== 'near_ed25519_and_ecdsa_wallet_registered') {
        throw new Error(`Mixed passkey registration returned result kind: ${result.kind}`);
      }
      return {
        ...passkeyRegistrationIdentitySummary({
          result,
          expectedWalletId: args.expectedWalletId,
        }),
        ecdsaTargetProfile: 'tempo_arc',
      };
    }
    default:
      return assertNever(args.ecdsaTargetProfile);
  }
}

function assertEd25519AddSignerSucceeded(
  result: RegistrationResult,
  expectedWalletId: string,
): Ed25519AddSignerResultSummary {
  if (!result.success) {
    throw new Error(result.error || 'Ed25519 add-signer failed');
  }
  if (result.kind !== 'near_ed25519_signer_added') {
    throw new Error(`Ed25519 add-signer returned result kind: ${result.kind}`);
  }
  const walletId = String(result.walletId).trim();
  if (walletId !== expectedWalletId) {
    throw new Error(`Ed25519 add-signer wallet mismatch: ${walletId}`);
  }
  const nearAccountId = String(result.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId).trim();
  const operationalPublicKey = String(result.operationalPublicKey ?? '').trim();
  if (!nearAccountId || !nearEd25519SigningKeyId || !operationalPublicKey) {
    throw new Error('Ed25519 add-signer returned incomplete signer identity');
  }
  return {
    kind: 'near_ed25519_signer_added',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    operationalPublicKey,
  };
}

type PasskeyWalletRegistrationResult = Extract<
  RegistrationResult,
  {
    success: true;
    kind: 'near_wallet_registered' | 'near_ed25519_and_ecdsa_wallet_registered';
  }
>;

type PasskeyRegistrationIdentitySummary = {
  kind: 'passkey_registration_success';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
};

function passkeyRegistrationIdentitySummary(args: {
  result: PasskeyWalletRegistrationResult;
  expectedWalletId: string;
}): PasskeyRegistrationIdentitySummary {
  const result = args.result;
  const walletId = String(result.walletId).trim();
  if (walletId !== args.expectedWalletId) {
    throw new Error(`Passkey registration wallet mismatch: ${walletId}`);
  }
  const nearAccountId = String(result.nearAccountId).trim();
  if (!nearAccountId) {
    throw new Error('Passkey registration did not return a NEAR account id');
  }
  const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId).trim();
  if (!nearEd25519SigningKeyId) {
    throw new Error('Passkey registration did not return an Ed25519 signing key id');
  }
  const operationalPublicKey = String(result.operationalPublicKey ?? '').trim();
  if (!operationalPublicKey) {
    throw new Error('Passkey registration did not return an operational public key');
  }
  return {
    kind: 'passkey_registration_success',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    operationalPublicKey,
  };
}

type EcdsaSessionFields = {
  thresholdEcdsaEthereumAddress?: string | null;
  thresholdEcdsaPublicKeyB64u?: string | null;
};

function assertEcdsaSessionSummary(args: {
  ecdsaTargetProfile: { kind: IntendedEcdsaTargetProfileName };
  source: EcdsaSessionFields;
  label: string;
}): IntendedEcdsaSessionSummary {
  const profile = args.ecdsaTargetProfile.kind;
  switch (profile) {
    case 'none':
      return {
        ecdsaTargetProfile: 'none',
      };
    case 'tempo': {
      const ecdsa = requireThresholdEcdsaSessionFields(args);
      return {
        ecdsaTargetProfile: 'tempo',
        thresholdEcdsaEthereumAddress: ecdsa.thresholdEcdsaEthereumAddress,
        thresholdEcdsaPublicKeyB64u: ecdsa.thresholdEcdsaPublicKeyB64u,
      };
    }
    case 'tempo_arc': {
      return {
        ecdsaTargetProfile: 'tempo_arc',
      };
    }
    default:
      return assertNever(profile);
  }
}

function requireThresholdEcdsaSessionFields(args: {
  source: EcdsaSessionFields;
  label: string;
}): Extract<IntendedEcdsaSessionSummary, { ecdsaTargetProfile: 'tempo' }> {
  const thresholdEcdsaEthereumAddress = String(
    args.source.thresholdEcdsaEthereumAddress || '',
  ).trim();
  if (!thresholdEcdsaEthereumAddress) {
    throw new Error(`${args.label} did not return a threshold ECDSA address`);
  }
  const thresholdEcdsaPublicKeyB64u = String(args.source.thresholdEcdsaPublicKeyB64u || '').trim();
  if (!thresholdEcdsaPublicKeyB64u) {
    throw new Error(`${args.label} did not return a threshold ECDSA public key`);
  }
  return {
    ecdsaTargetProfile: 'tempo',
    thresholdEcdsaEthereumAddress,
    thresholdEcdsaPublicKeyB64u,
  };
}

function assertEcdsaTargetKeysForSession(args: {
  session: IntendedEcdsaSessionSummary;
  ecdsaTargetKeys: IntendedEcdsaTargetKeysSummary;
}): IntendedEcdsaSummary {
  switch (args.session.ecdsaTargetProfile) {
    case 'none':
      if (args.ecdsaTargetKeys.kind !== 'none') {
        throw new Error(`ECDSA target key profile mismatch: ${args.ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'none',
        ecdsaTargetKeys: args.ecdsaTargetKeys,
      };
    case 'tempo':
      if (args.ecdsaTargetKeys.kind !== 'tempo') {
        throw new Error(`ECDSA target key profile mismatch: ${args.ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'tempo',
        thresholdEcdsaEthereumAddress: args.session.thresholdEcdsaEthereumAddress,
        thresholdEcdsaPublicKeyB64u: args.session.thresholdEcdsaPublicKeyB64u,
        ecdsaTargetKeys: args.ecdsaTargetKeys,
      };
    case 'tempo_arc':
      if (args.ecdsaTargetKeys.kind !== 'tempo_arc') {
        throw new Error(`ECDSA target key profile mismatch: ${args.ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'tempo_arc',
        ecdsaTargetKeys: args.ecdsaTargetKeys,
      };
    default:
      return assertNever(args.session);
  }
}

function assertEmailOtpRegistrationCompleted(args: {
  completed: {
    walletId: string;
    session: {
      login: {
        walletId: string | null;
        nearAccountId: string | null;
        publicKey: string | null;
        thresholdEcdsaEthereumAddress?: string | null;
        thresholdEcdsaPublicKeyB64u?: string | null;
      };
      signingSession: {
        status?: string;
        remainingUses?: number;
      } | null;
    };
  };
  initialWalletId: string;
  ecdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
}): EmailOtpRegistrationCoreSummary {
  const completed = args.completed;
  const walletId = String(completed.walletId || '').trim();
  if (!walletId) {
    throw new Error('Email OTP registration did not return walletId');
  }
  if (walletId === args.initialWalletId) {
    throw new Error('Email OTP registration reroll returned the initial walletId');
  }
  const sessionWalletId = String(completed.session.login.walletId || '').trim();
  if (sessionWalletId !== walletId) {
    throw new Error(`Email OTP registration session wallet mismatch: ${sessionWalletId}`);
  }
  const nearAccountId = String(completed.session.login.nearAccountId || '').trim();
  if (!nearAccountId) {
    throw new Error('Email OTP registration did not return a NEAR account id');
  }
  const operationalPublicKey = String(completed.session.login.publicKey || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Email OTP registration did not return an operational public key');
  }
  const ecdsa = assertEcdsaSessionSummary({
    ecdsaTargetProfile: args.ecdsaTargetProfile,
    source: completed.session.login,
    label: 'Email OTP registration',
  });
  const signingSessionStatus = String(completed.session.signingSession?.status || '').trim();
  if (signingSessionStatus !== 'active') {
    throw new Error(
      `Email OTP registration did not return an active signing session: ${signingSessionStatus}`,
    );
  }
  return {
    kind: 'email_otp_registration_success',
    initialWalletId: args.initialWalletId,
    walletId,
    nearAccountId,
    operationalPublicKey,
    signingSessionStatus,
    remainingUses: normalizeOptionalNumber(completed.session.signingSession?.remainingUses),
    ...ecdsa,
  };
}

function assertEmailOtpUnlockSucceeded(args: {
  result: {
    walletId: string;
    session: {
      login: {
        walletId: string | null;
        nearAccountId: string | null;
        publicKey: string | null;
        thresholdEcdsaEthereumAddress?: string | null;
        thresholdEcdsaPublicKeyB64u?: string | null;
      };
      signingSession: {
        status?: string;
        remainingUses?: number;
      } | null;
    };
  };
  expectedWalletId: string;
  ecdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
}): EmailOtpUnlockCoreSummary {
  const result = args.result;
  const walletId = String(result.walletId || '').trim();
  if (walletId !== args.expectedWalletId) {
    throw new Error(`Email OTP unlock wallet mismatch: ${walletId}`);
  }
  const sessionWalletId = String(result.session.login.walletId || '').trim();
  if (sessionWalletId !== walletId) {
    throw new Error(`Email OTP unlock session wallet mismatch: ${sessionWalletId}`);
  }
  const nearAccountId = String(result.session.login.nearAccountId || '').trim();
  if (!nearAccountId) {
    throw new Error('Email OTP unlock did not return a NEAR account id');
  }
  const operationalPublicKey = String(result.session.login.publicKey || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Email OTP unlock did not return an operational public key');
  }
  const ecdsa = assertEcdsaSessionSummary({
    ecdsaTargetProfile: args.ecdsaTargetProfile,
    source: result.session.login,
    label: 'Email OTP unlock',
  });
  const signingSessionStatus = String(result.session.signingSession?.status || '').trim();
  if (signingSessionStatus !== 'active') {
    throw new Error(
      `Email OTP unlock did not return an active signing session: ${signingSessionStatus}`,
    );
  }
  return {
    kind: 'email_otp_unlock_success',
    walletId,
    nearAccountId,
    operationalPublicKey,
    signingSessionStatus,
    remainingUses: normalizeOptionalNumber(result.session.signingSession?.remainingUses),
    ...ecdsa,
  };
}

function assertPasskeyUnlockSucceeded(
  result: Awaited<ReturnType<ReturnType<typeof useSeams>['seams']['auth']['unlock']>>,
  expectedWalletId: string,
): PasskeyUnlockResultSummary {
  if (!result.success) {
    throw new Error(result.error || 'Passkey unlock failed');
  }
  const nearAccountId = String(result.nearAccountId || '').trim();
  if (!nearAccountId) {
    throw new Error('Passkey unlock did not return a NEAR account id');
  }
  const operationalPublicKey = String(result.operationalPublicKey || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Passkey unlock did not return an operational public key');
  }
  const signingSessionStatus = String(result.signingSession?.status || '').trim();
  if (signingSessionStatus !== 'active') {
    throw new Error(
      `Passkey unlock did not return an active signing session: ${signingSessionStatus}`,
    );
  }
  return {
    kind: 'passkey_unlock_success',
    walletId: expectedWalletId,
    nearAccountId,
    operationalPublicKey,
    signingSessionStatus,
    remainingUses: normalizeOptionalNumber(result.signingSession?.remainingUses),
  };
}

function requireNearAccountId(nearAccountId: string | null): string {
  const value = String(nearAccountId || '').trim();
  if (!value) {
    throw new Error('NEAR signing requires nearAccountId');
  }
  return value;
}

function requireGoogleIdToken(googleIdToken: string | null): string {
  const value = String(googleIdToken || '').trim();
  if (!value) {
    throw new Error('Email OTP registration requires googleIdToken query param');
  }
  return value;
}

function requireEmailOtpChallengeId(challengeId: string): string {
  const value = String(challengeId || '').trim();
  if (!value) {
    throw new Error('Email OTP challengeId is required');
  }
  return value;
}

function requireWalletIdString(walletId: string): string {
  const value = String(walletId || '').trim();
  if (!value) {
    throw new Error('walletId is required');
  }
  return value;
}

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}

function requireRelayerUrl(relayerUrl: string | undefined): string {
  const value = String(relayerUrl || '').trim();
  if (!value) {
    throw new Error('Email OTP dev outbox requires relayer URL');
  }
  return value;
}

type EmailOtpCodeLookup =
  | {
      kind: 'challenge';
      challengeId: string;
    }
  | {
      kind: 'latest_for_wallet';
      challengeId?: never;
    };

function emailOtpDevOutboxUrl(input: {
  relayerUrl: string;
  walletId: string;
  lookup: EmailOtpCodeLookup;
}): string {
  const url = new URL('/wallet/email-otp/dev/otp-outbox', input.relayerUrl);
  url.searchParams.set('walletId', input.walletId);
  switch (input.lookup.kind) {
    case 'challenge':
      url.searchParams.set('challengeId', input.lookup.challengeId);
      return url.href;
    case 'latest_for_wallet':
      return url.href;
    default:
      return assertNever(input.lookup);
  }
}

function parseEmailOtpCodeLookup(input: IntendedEmailOtpCodeRequest): EmailOtpCodeLookup {
  switch (input.kind) {
    case 'challenge':
      return {
        kind: 'challenge',
        challengeId: requireEmailOtpChallengeId(input.challengeId),
      };
    case 'latest_for_wallet':
      return {
        kind: 'latest_for_wallet',
      };
    default:
      return assertNever(input);
  }
}

function googleEmailOtpLoginFlowChallengeId(input: { flowId: string; walletId: string }): string {
  const prefix = `google-email-otp-login:${input.walletId}:`;
  if (!input.flowId.startsWith(prefix)) {
    throw new Error(`Email OTP login flow id does not match wallet ${input.walletId}`);
  }
  return requireEmailOtpChallengeId(input.flowId.slice(prefix.length));
}

function parseEmailOtpOutboxSuccess(raw: unknown): IntendedEmailOtpOutboxSuccess {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Email OTP dev outbox returned invalid JSON');
  }
  const record = raw as Record<string, unknown>;
  if (record.ok !== true) {
    const message = typeof record.message === 'string' ? record.message : 'outbox lookup failed';
    throw new Error(`Email OTP dev outbox failed: ${message}`);
  }
  const otpCode = String(record.otpCode || '').trim();
  if (!/^\d{6}$/.test(otpCode)) {
    throw new Error('Email OTP dev outbox returned an invalid OTP code');
  }
  return {
    ok: true,
    otpCode,
  };
}

function installIntendedE2EHelpers(controller: IntendedPageController): void {
  if (typeof window === 'undefined') return;
  window.__seamsIntendedE2EReadEmailOtpCode = controller.readEmailOtpCodeForChallenge;
}

function requireHex(value: unknown, label: string): `0x${string}` {
  const hex = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${label} must be 0x-prefixed hex`);
  }
  return hex as `0x${string}`;
}

function normalizeOptionalNumber(value: unknown): number | null {
  if (value == null) return null;
  const normalized = Number(value);
  return Number.isFinite(normalized) ? normalized : null;
}

function normalizeSignedTransactionByteLength(signedTransaction: {
  borsh_bytes?: unknown;
}): number {
  if (Array.isArray(signedTransaction.borsh_bytes)) {
    return signedTransaction.borsh_bytes.length;
  }
  return 0;
}

function jsonSafeValue(value: unknown): unknown {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return String(value);
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

function assertNever(value: never): never {
  throw new Error(`Unexpected intended e2e state: ${String(value)}`);
}

const pageStyle: React.CSSProperties = {
  minHeight: '100vh',
  padding: '24px',
  background: '#f7f7f4',
  color: '#141414',
  fontFamily: 'system-ui, sans-serif',
};

const panelStyle: React.CSSProperties = {
  maxWidth: '880px',
  margin: '0 auto',
};

const headingStyle: React.CSSProperties = {
  margin: '0 0 16px',
  fontSize: '24px',
  lineHeight: 1.2,
};

const definitionListStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '100px minmax(0, 1fr)',
  gap: '8px 16px',
  margin: '0 0 20px',
};

const buttonRowStyle: React.CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '12px',
  marginBottom: '16px',
};

const buttonStyle: React.CSSProperties = {
  minHeight: '40px',
  padding: '0 16px',
  borderRadius: '6px',
  border: '1px solid #1f2937',
  background: '#1f2937',
  color: '#ffffff',
  fontWeight: 600,
};

const registrationActivationTargetStyle: React.CSSProperties = {
  position: 'relative',
  width: '280px',
  minHeight: '44px',
  borderRadius: '6px',
};

const statusStyle: React.CSSProperties = {
  display: 'block',
  marginBottom: '16px',
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
};

const snapshotStyle: React.CSSProperties = {
  minHeight: '280px',
  padding: '16px',
  overflow: 'auto',
  border: '1px solid #d5d5cf',
  borderRadius: '6px',
  background: '#ffffff',
  fontSize: '13px',
  lineHeight: 1.5,
};
