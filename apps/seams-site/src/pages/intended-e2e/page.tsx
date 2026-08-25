import React from 'react';
import type {
  NearProvisioningState,
  NearProvisioningStateChangedEvent,
  WalletSession,
} from '@seams/wallet';
import { buildHostedAuthMenuOpenRequest, hostedAuthMenuSessionIdFromBoundary } from '@seams/wallet';
import {
  ActionType,
  useSeams,
  type AddedNearEd25519SignerCapability,
  type GoogleEmailOtpWalletAuthEcdsaTargets,
  type RegisteredNearEd25519Capability,
  type RegistrationResult,
  type RegistrationSignerSetSelection,
} from '@seams/wallet/react';
import {
  encodeSignedTransactionBase64,
  nearAccountRefFromAccountId,
  parseWebAuthnRpId,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  walletSessionRefFromSession,
} from '@seams/wallet/advanced';
import { FRONTEND_CONFIG } from '@/config';

type IntendedActionName =
  | 'registerPasskeyWallet'
  | 'registerPasskeyEd25519YaoWallet'
  | 'registerPasskeyEcdsaOnlyWallet'
  | 'addPasskeyEd25519YaoWalletSigner'
  | 'addEmailOtpAuthMethod'
  | 'unlockWithAddedEmailOtp'
  | 'revokeSourceAuthMethod'
  | 'addPasskeyAuthMethod'
  | 'registerEmailOtpWallet'
  | 'registerEmailOtpEd25519OnlyWallet'
  | 'registerEmailOtpEcdsaOnlyWallet'
  | 'awaitNearReady'
  | 'syncPasskeyWallet'
  | 'recoverPasskeyWallet'
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
      thresholdEcdsaEthereumAddress: string;
      thresholdEcdsaPublicKeyB64u: string;
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

/**
 * Refactor 94 Phase 7. What a passkey registration can assert at return time
 * depends on whether it had a NEAR branch and whether that branch settled.
 * A NEAR-only plan resolves with its identity; a mixed plan resolves
 * ECDSA-ready with NEAR still provisioning, so no NEAR identifier exists yet.
 * Modelled as a closed union so neither branch can borrow the other's fields.
 */
/* Three readiness states, discriminated explicitly. 'absent' is a wallet whose
   signer set never included Ed25519: nothing is coming, unlike 'pending'. It
   forbids the identity and provisioning fields rather than leaving them
   optional, so a NEAR-less wallet cannot quietly carry a half-filled identity
   and no caller has to guess which of the three it holds. */
type PasskeyRegistrationCoreSummary = (
  | {
      kind: 'passkey_registration_success';
      walletId: string;
      nearReadiness: 'ready';
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      operationalPublicKey: string;
      nearProvisioning?: never;
    }
  | {
      kind: 'passkey_registration_success';
      walletId: string;
      nearReadiness: 'pending';
      nearProvisioning: IntendedNearProvisioningSummary;
      nearAccountId?: never;
      nearEd25519SigningKeyId?: never;
      operationalPublicKey?: never;
    }
  | {
      kind: 'passkey_registration_success';
      walletId: string;
      nearReadiness: 'absent';
      nearAccountId?: never;
      nearEd25519SigningKeyId?: never;
      operationalPublicKey?: never;
      nearProvisioning?: never;
    }
) &
  IntendedEcdsaSessionSummary;

type PasskeyRegistrationResultSummary = PasskeyRegistrationCoreSummary & IntendedEcdsaSummary;

type Ed25519AddSignerResultSummary = {
  kind: 'wallet_signer_added';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
};

type AddEmailOtpAuthMethodResultSummary = {
  kind: 'add_email_otp_success';
  walletAuthMethodId: string;
  walletId: string;
  emailAddress: string;
  authMethod: { kind: 'email_otp'; status: 'active' };
};

type AddPasskeyAuthMethodResultSummary = {
  kind: 'add_passkey_success';
  walletId: string;
  rpId: string;
  walletAuthMethodId: string;
  authMethod: { kind: 'passkey'; status: 'active' };
};

/* Same three readiness states as the passkey summary, for the same reason: an
   Email OTP wallet can own an ECDSA-only signer set too. */
type EmailOtpRegistrationCoreSummary = (
  | {
      kind: 'email_otp_registration_success';
      initialWalletId: string;
      walletId: string;
      nearReadiness: 'ready';
      nearAccountId: string;
      operationalPublicKey: string;
      nearProvisioning?: never;
      signingSessionStatus: string;
      remainingUses: number | null;
    }
  | {
      kind: 'email_otp_registration_success';
      initialWalletId: string;
      walletId: string;
      nearReadiness: 'pending';
      nearProvisioning: IntendedNearProvisioningSummary;
      nearAccountId?: never;
      operationalPublicKey?: never;
      signingSessionStatus: string;
      remainingUses: number | null;
    }
  | {
      kind: 'email_otp_registration_success';
      initialWalletId: string;
      walletId: string;
      nearReadiness: 'absent';
      nearAccountId?: never;
      operationalPublicKey?: never;
      nearProvisioning?: never;
      signingSessionStatus: string;
      remainingUses: number | null;
    }
) &
  IntendedEcdsaSessionSummary;

type EmailOtpRegistrationResultSummary = EmailOtpRegistrationCoreSummary & IntendedEcdsaSummary;

type NearSigningResultSummary = {
  kind: 'near_sign_success';
  walletId: string;
  nearAccountId: string;
  signedTransactionB64: string;
  signedTransactionByteLength: number;
};

type PasskeyUnlockResultSummary =
  | {
      kind: 'passkey_unlock_success';
      walletId: string;
      nearIdentity: 'ready';
      nearAccountId: string;
      operationalPublicKey: string;
      /** The exact credential the issued Wallet Session names. */
      sessionWalletAuthMethodId: string | null;
      signingSessionStatus: string;
      remainingUses: number | null;
    }
  | {
      kind: 'passkey_unlock_success';
      walletId: string;
      nearIdentity: 'absent';
      nearAccountId?: never;
      operationalPublicKey?: never;
      /** The exact credential the issued Wallet Session names. */
      sessionWalletAuthMethodId: string | null;
      signingSessionStatus: string;
      remainingUses: number | null;
    };

type PasskeySyncResultSummary = {
  kind: 'passkey_sync_success';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
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

/**
 * Refactor 109C: the Email OTP method just added opened its wallet.
 *
 * Leaner than the registered-wallet unlock summary on purpose. That one comes
 * from the Google flow, which discovers the wallet and reports its NEAR
 * identity on the way. An added method is enrolled under the address itself, so
 * the wallet is named directly and what this proves is narrower: this wallet
 * opened, under an active session, through the added method.
 */
type RevokeAuthMethodResultSummary = {
  kind: 'revoke_auth_method_success';
  walletId: string;
  walletAuthMethodId: string;
};

type AddedEmailOtpUnlockResultSummary = {
  kind: 'added_email_otp_unlock_success';
  walletId: string;
  /** The exact credential the issued Wallet Session names. */
  sessionWalletAuthMethodId: string | null;
  signingSessionStatus: string;
  remainingUses: number | null;
};

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

type NearProvisioningReadySummary = {
  kind: 'near_provisioning_ready';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
};

type PasskeyRecoveryResultSummary = {
  kind: 'passkey_recovery_success';
  walletId: string;
  activeRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
};

type IntendedActionResult =
  | PasskeyRegistrationResultSummary
  | Ed25519AddSignerResultSummary
  | AddEmailOtpAuthMethodResultSummary
  | AddPasskeyAuthMethodResultSummary
  | EmailOtpRegistrationResultSummary
  | NearProvisioningReadySummary
  | PasskeyRecoveryResultSummary
  | NearSigningResultSummary
  | PasskeySyncResultSummary
  | PasskeyUnlockResultSummary
  | EmailOtpUnlockResultSummary
  | AddedEmailOtpUnlockResultSummary
  | RevokeAuthMethodResultSummary
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

type IntendedNearProvisioningState = NearProvisioningState;

type IntendedNearProvisioningReadyState = Extract<
  IntendedNearProvisioningState,
  { status: 'near_ready' }
>;

type IntendedNearProvisioningSummary =
  | { status: 'pending'; error?: never; errorCode?: never }
  | { status: 'provisioning'; error?: never; errorCode?: never }
  | { status: 'retryable'; error: string; errorCode: string };

type IntendedEmailOtpOutboxSuccess = {
  ok: true;
  otpCode: string;
};

declare global {
  interface Window {
    __seamsIntendedE2EReadEmailOtpCode?: (input: IntendedEmailOtpCodeRequest) => Promise<string>;
    __seamsIntendedE2ELockWallet?: () => Promise<void>;
    __seamsIntendedE2EReadWalletLockState?: () => Promise<{
      reusableWalletSessionKind: WalletSession['reusableWalletSession']['kind'];
    }>;
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
const INTENDED_EVM_RECIPIENT: `0x${string}` = '0x1111111111111111111111111111111111111111';
const INTENDED_TEMPO_RECIPIENT: `0x${string}` = '0x2222222222222222222222222222222222222222';
const INTENDED_MAX_PRIORITY_FEE_PER_GAS = 1n;
const INTENDED_MAX_FEE_PER_GAS = 1n;
const INTENDED_EVM_GAS_LIMIT = 21_000n;

function intendedRegistrationRpId() {
  const parsed = parseWebAuthnRpId(FRONTEND_CONFIG.rpIdBase);
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
            data-testid="intended-register-passkey-ecdsa-only"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterPasskeyEcdsaOnlyWallet}
            style={buttonStyle}
          >
            Register ECDSA-only Wallet
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
            data-testid="intended-add-email-otp-auth-method"
            disabled={state.action.status === 'running'}
            onClick={controller.runAddEmailOtpAuthMethod}
            style={buttonStyle}
          >
            Add Email Code
          </button>
          <button
            type="button"
            data-testid="intended-revoke-source-auth-method"
            disabled={state.action.status === 'running'}
            onClick={controller.runRevokeSourceAuthMethod}
            style={buttonStyle}
          >
            Revoke Source Method
          </button>
          <button
            type="button"
            data-testid="intended-unlock-added-email-otp"
            disabled={state.action.status === 'running'}
            onClick={controller.runUnlockWithAddedEmailOtp}
            style={buttonStyle}
          >
            Unlock With Added Email Code
          </button>
          <button
            type="button"
            data-testid="intended-add-passkey-auth-method"
            disabled={state.action.status === 'running'}
            onClick={controller.runAddPasskeyAuthMethod}
            style={buttonStyle}
          >
            Add Passkey
          </button>
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
            data-testid="intended-register-email-otp-ecdsa-only"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterEmailOtpEcdsaOnlyWallet}
            style={buttonStyle}
          >
            Register ECDSA-only Email Wallet
          </button>
          <button
            type="button"
            data-testid="intended-register-email-otp-ed25519-only"
            disabled={state.action.status === 'running'}
            onClick={controller.runRegisterEmailOtpEd25519OnlyWallet}
            style={buttonStyle}
          >
            Register Ed25519-only Email Wallet
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
            data-testid="intended-await-near-ready"
            disabled={state.action.status === 'running'}
            onClick={controller.runAwaitNearReady}
            style={buttonStyle}
          >
            Await NEAR Ready
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
            data-testid="intended-sync-passkey"
            disabled={state.action.status === 'running'}
            onClick={controller.runSyncPasskeyWallet}
            style={buttonStyle}
          >
            Sync Passkey
          </button>
          <button
            type="button"
            data-testid="intended-recover-passkey"
            disabled={state.action.status === 'running'}
            onClick={controller.runRecoverPasskeyWallet}
            style={buttonStyle}
          >
            Recover Passkey
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

  runAddPasskeyEd25519YaoWalletSigner = (): void => {
    void this.addPasskeyEd25519YaoWalletSigner();
  };

  runAddEmailOtpAuthMethod = (): void => {
    void this.addEmailOtpAuthMethod();
  };

  runUnlockWithAddedEmailOtp = (): void => {
    void this.unlockWithAddedEmailOtp();
  };

  runRegisterPasskeyEcdsaOnlyWallet = (): void => {
    void this.registerPasskeyEcdsaOnlyWallet();
  };

  runRevokeSourceAuthMethod = (): void => {
    void this.revokeSourceAuthMethod();
  };

  runAddPasskeyAuthMethod = (): void => {
    void this.addPasskeyAuthMethod();
  };

  runRegisterEmailOtpWallet = (): void => {
    void this.registerEmailOtpWallet();
  };

  runRegisterEmailOtpEd25519OnlyWallet = (): void => {
    void this.registerEmailOtpEd25519OnlyWallet();
  };

  runRegisterEmailOtpEcdsaOnlyWallet = (): void => {
    void this.registerEmailOtpEcdsaOnlyWallet();
  };

  runAwaitNearReady = (): void => {
    void this.awaitNearReady();
  };

  runSignNearTransaction = (): void => {
    void this.signNearTransaction();
  };

  runUnlockPasskeyWallet = (): void => {
    void this.unlockPasskeyWallet();
  };

  runSyncPasskeyWallet = (): void => {
    void this.syncPasskeyWallet();
  };

  runRecoverPasskeyWallet = (): void => {
    void this.recoverPasskeyWallet();
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

  lockWalletForIntendedTest = async (): Promise<void> => {
    await this.seams.auth.lock();
    await this.refreshLoginState(this.walletId);
  };

  readWalletLockStateForIntendedTest = async (): Promise<{
    reusableWalletSessionKind: WalletSession['reusableWalletSession']['kind'];
  }> => {
    const session = await this.seams.auth.getWalletSession(this.walletId);
    return { reusableWalletSessionKind: session.reusableWalletSession.kind };
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
        recoveryCodeBackup: { kind: 'show_builtin_dialog' },
        onEvent: this.recordLifecycleEvent,
      });
      const registration = assertPasskeyRegistrationSucceeded({
        result,
        expectedWalletId: this.walletId,
        ecdsaTargetProfile: this.passkeyEcdsaTargetProfile,
      });
      const ecdsaTargetKeys = registrationEcdsaTargetKeys(registration);
      const ecdsa = assertEcdsaTargetKeysForSession({
        session: registration,
        ecdsaTargetKeys,
      });
      /* A mixed plan has no NEAR identity yet; a NEAR-only plan does. The two
         summary branches cannot be merged without reintroducing optional
         lifecycle fields. */
      const summary: PasskeyRegistrationResultSummary =
        registration.nearReadiness === 'pending'
          ? {
              kind: registration.kind,
              walletId: registration.walletId,
              nearReadiness: 'pending',
              nearProvisioning: registration.nearProvisioning,
              ...ecdsa,
            }
          : registration.nearReadiness === 'ready'
            ? {
                kind: registration.kind,
                walletId: registration.walletId,
                nearReadiness: 'ready',
                nearAccountId: registration.nearAccountId,
                nearEd25519SigningKeyId: registration.nearEd25519SigningKeyId,
                operationalPublicKey: registration.operationalPublicKey,
                ...ecdsa,
              }
            : {
                kind: registration.kind,
                walletId: registration.walletId,
                nearReadiness: 'absent',
                ...ecdsa,
              };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /**
   * Refactor 109C matrix: a wallet whose signer set is ECDSA only.
   *
   * The combined wallets the transition contracts use always have an Ed25519
   * signer for an added method to inherit. This one has none, so an added
   * method must correctly claim no Ed25519 rather than fail looking for one.
   */
  private async registerPasskeyEcdsaOnlyWallet(): Promise<void> {
    const action: IntendedActionName = 'registerPasskeyEcdsaOnlyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const sdkTargets = this.emailOtpEcdsaTargetProfile.sdkTargets;
      if (sdkTargets.kind !== 'explicit') {
        throw new Error('ECDSA-only registration requires configured chain targets');
      }
      const result = await this.seams.registration.registerWallet({
        authMethod: { kind: 'passkey', rpId: intendedRegistrationRpId() },
        wallet: { kind: 'provided', walletId: toWalletId(this.walletId) },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'evm_family_ecdsa',
              chainTargets: [...sdkTargets.targets],
              participantIds: [1, 2],
            },
          ],
        },
        options: { onEvent: this.recordLifecycleEvent },
      });
      if (!result.success) throw new Error(result.error || 'ECDSA-only registration failed');
      if (
        result.kind !== 'wallet_registered' ||
        result.capabilities.length !== 1 ||
        result.capabilities[0].kind !== 'evm_family_ecdsa'
      ) {
        throw new Error(`ECDSA-only registration returned result kind: ${result.kind}`);
      }
      if (String(result.walletId) !== this.walletId) {
        throw new Error('ECDSA-only registration returned a different wallet');
      }
      const ecdsa = requireThresholdEcdsaSessionFields({
        source: result.capabilities[0],
        label: 'ECDSA-only registration',
      });
      /* The profile follows the configured targets rather than being asserted,
         and the per-target keys are derived from the threshold address the same
         way every other registration derives them. */
      const session: IntendedEcdsaSessionSummary =
        sdkTargets.targets.length > 1
          ? {
              ecdsaTargetProfile: 'tempo_arc',
              thresholdEcdsaEthereumAddress: ecdsa.thresholdEcdsaEthereumAddress,
              thresholdEcdsaPublicKeyB64u: ecdsa.thresholdEcdsaPublicKeyB64u,
            }
          : {
              ecdsaTargetProfile: 'tempo',
              thresholdEcdsaEthereumAddress: ecdsa.thresholdEcdsaEthereumAddress,
              thresholdEcdsaPublicKeyB64u: ecdsa.thresholdEcdsaPublicKeyB64u,
            };
      const summary = {
        kind: 'passkey_registration_success' as const,
        walletId: this.walletId,
        nearReadiness: 'absent' as const,
        ...session,
        ecdsaTargetKeys: registrationEcdsaTargetKeys(session),
      } as PasskeyRegistrationResultSummary;
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
      if (registration.nearReadiness !== 'ready') {
        throw new Error('Ed25519-only passkey registration must resolve its NEAR identity');
      }
      const summary: PasskeyRegistrationResultSummary = {
        kind: registration.kind,
        walletId: registration.walletId,
        nearReadiness: 'ready',
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
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /**
   * Refactor 109C: the passkey wallet on screen gains an Email OTP method.
   *
   * The address is derived from the wallet so repeated runs against a
   * persistent local stack do not fight over one provider identity — an
   * enrollment is per wallet and per identity, and a shared address would make
   * each run move the previous run's enrollment.
   */
  private async addEmailOtpAuthMethod(): Promise<void> {
    const action: IntendedActionName = 'addEmailOtpAuthMethod';
    this.dispatch({ kind: 'action_started', action });
    try {
      const walletId = this.walletId;
      if (!walletId) throw new Error('add-email-code requires a registered wallet');
      const emailAddress = intendedAddEmailOtpAddress(walletId);
      intendedEmailOtpChallengeSubjectOverride = emailAddress;
      const result = await this.seams.registration.addEmailOtp({
        walletId: toWalletId(walletId),
        emailAddress,
        options: { onEvent: this.recordLifecycleEvent },
      });
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'add_email_otp_success',
          walletId: String(result.walletId),
          walletAuthMethodId: String(result.walletAuthMethodId),
          emailAddress: result.emailAddress,
          authMethod: result.authMethod,
        },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /**
   * Refactor 109C: retire the method that did the adding, from the added one.
   *
   * The sibling that stays is the one just added, so this is the case that
   * matters: a wallet must not become unopenable because the credential it was
   * created with was removed.
   */
  private async revokeSourceAuthMethod(): Promise<void> {
    const action: IntendedActionName = 'revokeSourceAuthMethod';
    this.dispatch({ kind: 'action_started', action });
    try {
      const walletId = this.walletId;
      if (!walletId) throw new Error('revoke requires a registered wallet');
      const session = await this.seams.auth.getWalletSession(walletId);
      if (session.appIdentity.kind !== 'resolved') {
        throw new Error(`revoke wallet identity is ${session.appIdentity.kind}`);
      }
      /* With one method there is nothing to revoke from, whatever the session
         is doing - say that before asking about the session, so the refusal
         names the real reason rather than whichever check happened first. */
      const methods = session.appIdentity.authMethods;
      if (methods.length <= 1) {
        throw new Error(
          `revoke needs exactly one sibling to remove, found ${Math.max(methods.length - 1, 0)}`,
        );
      }
      /* Whoever holds the open session is the method to keep. Deriving the
         target this way needs no memory of the addition, which matters because
         the page reloads between actions. */
      const active = session.reusableWalletSession;
      if (active.kind !== 'active') {
        throw new Error(`revoke requires an active Wallet Session, found ${active.kind}`);
      }
      const keep = String(active.walletAuthMethodId);
      const siblings = methods.filter((binding) => String(binding.walletAuthMethodId) !== keep);
      const [target, ...remaining] = siblings;
      if (!target || remaining.length > 0) {
        throw new Error(
          `revoke needs exactly one sibling to remove, found ${siblings.length} beside the added method`,
        );
      }
      const result = await this.seams.registration.revokeAuthMethod({
        walletId: toWalletId(walletId),
        walletAuthMethodId: String(target.walletAuthMethodId),
      });
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'revoke_auth_method_success',
          walletId: String(result.walletId),
          walletAuthMethodId: String(result.walletAuthMethodId),
        },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /**
   * Refactor 109C: unlock through the Email OTP method the wallet just added.
   *
   * Deliberately not `unlockEmailOtpWallet`, which resolves the wallet from a
   * Google subject. An added method carries the verified address as its own
   * provider identity, so there is no subject to discover from - the wallet is
   * named, the address is the identity, and the code proves control of it.
   */
  private async unlockWithAddedEmailOtp(): Promise<void> {
    const action: IntendedActionName = 'unlockWithAddedEmailOtp';
    this.dispatch({ kind: 'action_started', action });
    try {
      const walletId = this.walletId;
      if (!walletId) throw new Error('added email-code unlock requires a registered wallet');
      const emailAddress = intendedAddEmailOtpAddress(walletId);
      intendedEmailOtpChallengeSubjectOverride = emailAddress;
      /* Read before locking: the unlock names the exact method it opens, and
         once the wallet is locked there is no session left to ask. */
      const openSession = await this.seams.auth.getWalletSession(walletId);
      if (openSession.appIdentity.kind !== 'resolved') {
        throw new Error(`added email-code unlock identity is ${openSession.appIdentity.kind}`);
      }
      const emailBindings = openSession.appIdentity.authMethods.filter(
        (binding) => binding.kind === 'email_otp',
      );
      const [addedBinding, ...extraBindings] = emailBindings;
      if (!addedBinding || extraBindings.length > 0) {
        throw new Error(
          `added email-code unlock needs one email method, found ${emailBindings.length}`,
        );
      }
      const addedMethodId = String(addedBinding.walletAuthMethodId);
      await this.seams.auth.lock();
      const challenge = await this.seams.auth.requestEmailOtpChallenge({
        walletId,
        onEvent: this.recordLifecycleEvent,
      });
      const otpCode = await this.readEmailOtpCodeForChallenge({
        kind: 'challenge',
        challengeId: challenge.challengeId,
        walletId,
      });
      /* `unlockAddedEmailOtpWallet` now resolves and selects this exact method,
         but then asks for linked-device signer material an owner-side sibling
         does not have. Until the added method has its own signer access, the
         added method opens its ECDSA capability directly. */
      const sdkTargets = this.emailOtpEcdsaTargetProfile.sdkTargets;
      if (sdkTargets.kind !== 'explicit') {
        throw new Error('added email-code unlock requires a configured ECDSA target');
      }
      const [chainTarget] = sdkTargets.targets;
      void addedMethodId;
      await this.seams.auth.loginWithEmailOtpEcdsaCapability({
        walletSession: { walletId: toWalletId(walletId), walletSessionUserId: walletId },
        chainTarget,
        providerIdentity: { provider: 'email', providerSubjectId: emailAddress },
        emailOtpAuthorityEmail: emailAddress,
        challengeId: challenge.challengeId,
        otpCode,
        onEvent: this.recordLifecycleEvent,
      });
      await this.refreshLoginState(walletId);
      const unlockedSession = await this.seams.auth.getWalletSession(walletId);
      const reusable = unlockedSession.reusableWalletSession;
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'added_email_otp_unlock_success',
          walletId,
          sessionWalletAuthMethodId:
            reusable.kind === 'active' ? String(reusable.walletAuthMethodId) : null,
          signingSessionStatus: reusable.kind,
          remainingUses: null,
        },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /** Refactor 109C: an Email OTP wallet adds a Passkey on the same authority. */
  private async addPasskeyAuthMethod(): Promise<void> {
    const action: IntendedActionName = 'addPasskeyAuthMethod';
    this.dispatch({ kind: 'action_started', action });
    try {
      const walletId = this.walletId;
      if (!walletId) throw new Error('add-passkey requires a registered wallet');
      /* No source proof is assembled here. The wallet resolves its own selected
         Email OTP method, sends the intent-bound code, and prompts for it. */
      const result = await this.seams.registration.addPasskey({
        walletId: toWalletId(walletId),
        rpId: intendedRegistrationRpId(),
        options: { onEvent: this.recordLifecycleEvent },
      });
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'add_passkey_success',
          walletId: String(result.walletId),
          rpId: String(result.rpId),
          walletAuthMethodId: String(result.walletAuthMethodId),
          authMethod: result.authMethod,
        },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /**
   * Refactor 109C matrix: an Email OTP wallet whose signer set is Ed25519 only.
   *
   * Same registration flow as every other Email OTP wallet; only the signer
   * set differs, which is the point - a parallel registration variant would
   * prove something about the variant rather than about this flow.
   */
  private async registerEmailOtpEd25519OnlyWallet(): Promise<void> {
    const action: IntendedActionName = 'registerEmailOtpEd25519OnlyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const registration = await this.registerEmailOtpWalletWithPublicSdk(
        intendedEd25519YaoSignerSelection(),
      );
      this.walletId = registration.walletId;
      this.nearAccountId = registration.nearAccountId ?? null;
      if (registration.ecdsaTargetProfile !== 'none') {
        throw new Error('Ed25519-only Email OTP registration provisioned an ECDSA signer');
      }
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: { ...registration, ecdsaTargetKeys: { kind: 'none' } },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  /** Refactor 109C matrix: an Email OTP wallet whose signer set is ECDSA only. */
  private async registerEmailOtpEcdsaOnlyWallet(): Promise<void> {
    const action: IntendedActionName = 'registerEmailOtpEcdsaOnlyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const sdkTargets = this.emailOtpEcdsaTargetProfile.sdkTargets;
      if (sdkTargets.kind !== 'explicit') {
        throw new Error('ECDSA-only Email OTP registration requires configured chain targets');
      }
      const registration = await this.registerEmailOtpWalletWithPublicSdk({
        kind: 'signer_set',
        signers: [
          {
            kind: 'evm_family_ecdsa',
            chainTargets: [...sdkTargets.targets],
            participantIds: [1, 2],
          },
        ],
      });
      this.walletId = registration.walletId;
      this.nearAccountId = registration.nearAccountId ?? null;
      const ecdsaTargetKeys = registrationEcdsaTargetKeys(registration);
      const ecdsa = assertEcdsaTargetKeysForSession({ session: registration, ecdsaTargetKeys });
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: { ...registration, ...ecdsa } as EmailOtpRegistrationResultSummary,
      });
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
      this.nearAccountId = registration.nearAccountId ?? null;
      const ecdsaTargetKeys = registrationEcdsaTargetKeys(registration);
      const ecdsa = assertEcdsaTargetKeysForSession({
        session: registration,
        ecdsaTargetKeys,
      });
      /* Branch on the arm rather than copying members out: the result carries a
         resolved identity, a provisioning status, or neither, and flattening
         them into one object loses exactly that guarantee. */
      const common = {
        kind: registration.kind,
        initialWalletId: registration.initialWalletId,
        walletId: registration.walletId,
        signingSessionStatus: registration.signingSessionStatus,
        remainingUses: registration.remainingUses,
      };
      const summary: EmailOtpRegistrationResultSummary =
        registration.nearReadiness === 'pending'
          ? {
              ...common,
              nearReadiness: 'pending',
              nearProvisioning: registration.nearProvisioning,
              ...ecdsa,
            }
          : registration.nearReadiness === 'ready'
            ? {
                ...common,
                nearReadiness: 'ready',
                nearAccountId: registration.nearAccountId,
                operationalPublicKey: registration.operationalPublicKey,
                ...ecdsa,
              }
            : { ...common, nearReadiness: 'absent', ...ecdsa };
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async awaitNearReady(): Promise<void> {
    const action: IntendedActionName = 'awaitNearReady';
    this.dispatch({ kind: 'action_started', action });
    try {
      const state = await awaitWalletNearReady({
        registration: this.seams.registration,
        walletId: this.walletId,
      });
      const session = await this.seams.auth.getWalletSession(this.walletId);
      if (session.appIdentity.kind !== 'resolved') {
        throw new Error(`NEAR readiness wallet identity is ${session.appIdentity.kind}`);
      }
      const nearAccountId = String(session.appIdentity.nearAccountId ?? '').trim();
      const operationalPublicKey = String(
        session.appIdentity.nearOperationalPublicKey ?? '',
      ).trim();
      if (nearAccountId !== state.nearAccountId || !operationalPublicKey) {
        throw new Error('NEAR provisioning completed without a matching wallet session identity');
      }
      this.nearAccountId = nearAccountId;
      await this.refreshLoginState(this.walletId);
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'near_provisioning_ready',
          walletId: this.walletId,
          nearAccountId,
          operationalPublicKey,
        },
      });
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
      /* R109C: which credential the session names is the point of an added
         method - the family alone cannot tell it from the method that added it. */
      const unlockedSession = await this.seams.auth.getWalletSession(this.walletId);
      const reusable = unlockedSession.reusableWalletSession;
      const summary = assertPasskeyUnlockSucceeded(
        result,
        this.walletId,
        reusable.kind === 'active' ? String(reusable.walletAuthMethodId) : null,
      );
      await this.refreshLoginState(summary.walletId);
      this.dispatch({ kind: 'action_succeeded', action, result: summary });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async syncPasskeyWallet(): Promise<void> {
    const action: IntendedActionName = 'syncPasskeyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(
        `intended-passkey-sync-${crypto.randomUUID()}`,
      );
      if (!authMenuSessionId) throw new Error('Passkey sync auth-menu identity is invalid');
      const anchorElement = document.querySelector<HTMLElement>(
        '[data-testid="intended-sync-passkey"]',
      );
      if (!anchorElement) throw new Error('Passkey sync anchor is unavailable');
      const outcome = await this.seams.openHostedAuthMenu(
        buildHostedAuthMenuOpenRequest({
          authMenuSessionId,
          initialMode: 'login',
          loginTarget: { kind: 'wallet_sync', walletId: toWalletId(this.walletId) },
          registrationAccountInput: 'implicit_wallet',
          showRegistrationInput: false,
          showProgress: true,
          enabledExternalProviders: [],
        }),
        anchorElement,
      );
      if (outcome.kind !== 'account_synced') {
        throw new Error(`Passkey sync ended with ${outcome.kind}`);
      }
      if (String(outcome.walletId) !== this.walletId) {
        throw new Error(`Passkey sync wallet mismatch: ${String(outcome.walletId)}`);
      }
      const session = await this.seams.auth.getWalletSession(String(outcome.walletId));
      if (session.appIdentity.kind !== 'resolved') {
        throw new Error(`Passkey sync wallet identity is ${session.appIdentity.kind}`);
      }
      const nearAccountId = String(session.appIdentity.nearAccountId ?? '').trim();
      const operationalPublicKey = String(
        session.appIdentity.nearOperationalPublicKey ?? '',
      ).trim();
      if (!nearAccountId || !operationalPublicKey) {
        throw new Error('Passkey sync omitted its NEAR signer identity');
      }
      this.nearAccountId = nearAccountId;
      await this.refreshLoginState(String(outcome.walletId));
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'passkey_sync_success',
          walletId: String(outcome.walletId),
          nearAccountId,
          operationalPublicKey,
        },
      });
    } catch (error) {
      this.dispatch({ kind: 'action_failed', action, error: errorMessage(error) });
    }
  }

  private async recoverPasskeyWallet(): Promise<void> {
    const action: IntendedActionName = 'recoverPasskeyWallet';
    this.dispatch({ kind: 'action_started', action });
    try {
      const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(
        `intended-passkey-recovery-${crypto.randomUUID()}`,
      );
      if (!authMenuSessionId) throw new Error('Passkey recovery auth-menu identity is invalid');
      const anchorElement = document.querySelector<HTMLElement>(
        '[data-testid="intended-recover-passkey"]',
      );
      if (!anchorElement) throw new Error('Passkey recovery anchor is unavailable');
      const outcome = await this.seams.openHostedAuthMenu(
        buildHostedAuthMenuOpenRequest({
          authMenuSessionId,
          initialMode: 'login',
          loginTarget: { kind: 'wallet', walletId: toWalletId(this.walletId) },
          registrationAccountInput: 'implicit_wallet',
          showRegistrationInput: false,
          showProgress: true,
          enabledExternalProviders: [],
        }),
        anchorElement,
      );
      if (outcome.kind !== 'authenticated') {
        throw new Error(`Passkey recovery ended with ${outcome.kind}`);
      }
      if (String(outcome.walletId) !== this.walletId || outcome.method !== 'passkey') {
        throw new Error('Passkey recovery returned the wrong wallet or auth method');
      }
      await this.refreshLoginState(String(outcome.walletId));
      const recoveryStatus = await this.seams.recovery.getWalletRecoveryCodeStatus({
        walletId: String(outcome.walletId),
      });
      if (recoveryStatus.kind !== 'ready') {
        throw new Error(`Recovery-code status is ${recoveryStatus.kind}`);
      }
      this.dispatch({
        kind: 'action_succeeded',
        action,
        result: {
          kind: 'passkey_recovery_success',
          walletId: String(outcome.walletId),
          activeRecoveryCodeCount: recoveryStatus.activeCodeCount,
          totalRecoveryCodeCount: recoveryStatus.totalCodeCount,
        },
      });
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

  private async registerEmailOtpWalletWithPublicSdk(
    signerSelection?: RegistrationSignerSetSelection,
  ): Promise<EmailOtpRegistrationCoreSummary> {
    const idToken = requireGoogleIdToken(this.googleIdToken);
    /* The profile follows the selection when one is given, and is then used for
       both the request and the assertion. Asking for ECDSA targets while
       registering an Ed25519-only set makes the flow expect a threshold address
       the wallet was never going to have. */
    const effectiveEcdsaProfile: IntendedEmailOtpEcdsaTargetProfile =
      signerSelection &&
      !signerSelection.signers.some((signer) => signer.kind === 'evm_family_ecdsa')
        ? { kind: 'none', sdkTargets: { kind: 'none' }, chainTargets: [] }
        : this.emailOtpEcdsaTargetProfile;
    const flowResult = await this.seams.auth.beginGoogleEmailOtpWalletAuth({
      idToken,
      mode: 'register',
      // The harness registers a fresh wallet per run against a persistent
      // local stack; the fixed Google test subject may already hold one.
      replaceExistingWallet: true,
      ecdsaTargets: effectiveEcdsaProfile.sdkTargets,
      ...(signerSelection ? { signerSelection } : {}),
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
    const nearProvisioning = await this.seams.registration.getNearProvisioningState({
      walletId: completed.value.walletId,
    });
    return assertEmailOtpRegistrationCompleted({
      completed: completed.value,
      initialWalletId,
      ecdsaTargetProfile: effectiveEcdsaProfile,
      nearProvisioning,
    });
  }

  private async unlockEmailOtpWalletWithPublicSdk(): Promise<EmailOtpUnlockCoreSummary> {
    const idToken = requireGoogleIdToken(this.googleIdToken);
    const flowResult = await this.seams.auth.beginGoogleEmailOtpWalletAuth({
      idToken,
      mode: 'login',
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
    const url = emailOtpDevOutboxUrl({
      relayerUrl: requireRelayerUrl(this.seams.configs.network.relayer?.url),
    });
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        idToken,
        walletId,
        ...(lookup.kind === 'challenge' ? { challengeId: lookup.challengeId } : {}),
        /* Only alongside the exact challenge. The route refuses a named subject
           without one, so the fallback lookup stays on the token's identity. */
        ...(lookup.kind === 'challenge' && intendedEmailOtpChallengeSubjectOverride
          ? { challengeSubjectId: intendedEmailOtpChallengeSubjectOverride }
          : {}),
      }),
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
    const result = await this.seams.evm.signTransaction({
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
      materialActivation: resolvedLane.materialActivation,
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
    case 'wallet_signer_added':
    case 'add_email_otp_success':
    case 'add_passkey_success':
    case 'email_otp_registration_success':
    case 'near_provisioning_ready':
    case 'near_sign_success':
    case 'passkey_unlock_success':
    case 'passkey_sync_success':
    case 'passkey_recovery_success':
    case 'email_otp_unlock_success':
    case 'added_email_otp_unlock_success':
    case 'revoke_auth_method_success':
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
    case 'wallet_signer_added':
    case 'email_otp_registration_success':
    case 'near_provisioning_ready':
    case 'near_sign_success':
    case 'passkey_sync_success':
    case 'email_otp_unlock_success':
    case 'ed25519_export_success':
      return result.nearAccountId ?? null;
    case 'passkey_unlock_success':
      return result.nearIdentity === 'ready' ? result.nearAccountId : null;
    /* An added auth method changes who can unlock the wallet, not which NEAR
       account it signs for. */
    case 'add_email_otp_success':
    case 'add_passkey_success':
    case 'added_email_otp_unlock_success':
    case 'revoke_auth_method_success':
    case 'tempo_sign_success':
    case 'arc_evm_sign_success':
    case 'ecdsa_export_success':
    case 'passkey_recovery_success':
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
    case 'wallet_signer_added':
      return 2;
    case 'near_provisioning_ready':
      return 1;
    case 'near_sign_success':
    case 'passkey_unlock_success':
    case 'passkey_sync_success':
    case 'passkey_recovery_success':
    case 'email_otp_unlock_success':
    case 'added_email_otp_unlock_success':
    case 'revoke_auth_method_success':
    case 'add_email_otp_success':
    case 'add_passkey_success':
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
      if (
        result.kind !== 'wallet_registered' ||
        result.capabilities.length !== 1 ||
        result.capabilities[0].kind !== 'near_ed25519'
      ) {
        throw new Error(`NEAR-only passkey registration returned result kind: ${result.kind}`);
      }
      return {
        ...passkeyRegistrationIdentitySummary({
          walletId: result.walletId,
          capability: result.capabilities[0],
          expectedWalletId: args.expectedWalletId,
        }),
        ecdsaTargetProfile: 'none',
      };
    }
    case 'tempo': {
      /* Refactor 94 Phase 7. A mixed plan resolves ECDSA-ready with the NEAR
         branch still settling, so registration reports no NEAR identity here.
         Callers that need it await near_ready through the public provisioning
         API rather than reading it off the registration result. */
      if (result.kind !== 'ecdsa_wallet_registered_near_pending') {
        throw new Error(`Mixed passkey registration returned result kind: ${result.kind}`);
      }
      const ecdsa = requireThresholdEcdsaSessionFields({
        source: result.capabilities[0],
        label: 'Passkey registration',
      });
      return {
        ...pendingPasskeyRegistrationSummary({
          result,
          expectedWalletId: args.expectedWalletId,
        }),
        ...ecdsa,
      };
    }
    case 'tempo_arc': {
      if (result.kind !== 'ecdsa_wallet_registered_near_pending') {
        throw new Error(`Mixed passkey registration returned result kind: ${result.kind}`);
      }
      const ecdsa = requireThresholdEcdsaSessionFields({
        source: result.capabilities[0],
        label: 'Passkey registration',
      });
      return {
        ...pendingPasskeyRegistrationSummary({
          result,
          expectedWalletId: args.expectedWalletId,
        }),
        ecdsaTargetProfile: 'tempo_arc',
        thresholdEcdsaEthereumAddress: ecdsa.thresholdEcdsaEthereumAddress,
        thresholdEcdsaPublicKeyB64u: ecdsa.thresholdEcdsaPublicKeyB64u,
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
  if (
    result.kind !== 'wallet_signer_added' ||
    result.capabilities.length !== 1 ||
    result.capabilities[0].kind !== 'near_ed25519'
  ) {
    throw new Error(`Ed25519 add-signer returned result kind: ${result.kind}`);
  }
  const capability: AddedNearEd25519SignerCapability = result.capabilities[0];
  const walletId = String(result.walletId).trim();
  if (walletId !== expectedWalletId) {
    throw new Error(`Ed25519 add-signer wallet mismatch: ${walletId}`);
  }
  const nearAccountId = String(capability.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(capability.nearEd25519SigningKeyId).trim();
  const operationalPublicKey = String(capability.operationalPublicKey ?? '').trim();
  if (!nearAccountId || !nearEd25519SigningKeyId || !operationalPublicKey) {
    throw new Error('Ed25519 add-signer returned incomplete signer identity');
  }
  return {
    kind: 'wallet_signer_added',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    operationalPublicKey,
  };
}

type PendingPasskeyWalletRegistrationResult = Extract<
  RegistrationResult,
  { success: true; kind: 'ecdsa_wallet_registered_near_pending' }
>;

type PendingPasskeyRegistrationIdentitySummary = {
  kind: 'passkey_registration_success';
  walletId: string;
  nearReadiness: 'pending';
  nearProvisioning: IntendedNearProvisioningSummary;
};

type PasskeyRegistrationIdentitySummary = {
  kind: 'passkey_registration_success';
  walletId: string;
  nearReadiness: 'ready';
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
};

/**
 * Identity a mixed passkey registration can actually assert at return time.
 * NEAR provisioning has not completed, so there is no NEAR account, signing
 * key id, or operational public key to report yet.
 */
function pendingPasskeyRegistrationSummary(args: {
  result: PendingPasskeyWalletRegistrationResult;
  expectedWalletId: string;
}): PendingPasskeyRegistrationIdentitySummary {
  const walletId = String(args.result.walletId).trim();
  if (walletId !== args.expectedWalletId) {
    throw new Error(`Passkey registration wallet mismatch: ${walletId}`);
  }
  return {
    kind: 'passkey_registration_success',
    walletId,
    nearReadiness: 'pending',
    nearProvisioning: registrationNearProvisioningSummary(args.result.nearProvisioning),
  };
}

function registrationNearProvisioningSummary(
  state: PendingPasskeyWalletRegistrationResult['nearProvisioning'],
): IntendedNearProvisioningSummary {
  switch (state.status) {
    case 'pending':
      return { status: 'pending' };
    case 'retryable':
      return { status: 'retryable', error: state.error, errorCode: state.errorCode };
    default:
      return assertNever(state);
  }
}

function passkeyRegistrationIdentitySummary(args: {
  walletId: string;
  capability: RegisteredNearEd25519Capability;
  expectedWalletId: string;
}): PasskeyRegistrationIdentitySummary {
  const walletId = String(args.walletId).trim();
  if (walletId !== args.expectedWalletId) {
    throw new Error(`Passkey registration wallet mismatch: ${walletId}`);
  }
  const nearAccountId = String(args.capability.nearAccountId).trim();
  if (!nearAccountId) {
    throw new Error('Passkey registration did not return a NEAR account id');
  }
  const nearEd25519SigningKeyId = String(args.capability.nearEd25519SigningKeyId).trim();
  if (!nearEd25519SigningKeyId) {
    throw new Error('Passkey registration did not return an Ed25519 signing key id');
  }
  const operationalPublicKey = String(args.capability.operationalPublicKey ?? '').trim();
  if (!operationalPublicKey) {
    throw new Error('Passkey registration did not return an operational public key');
  }
  return {
    kind: 'passkey_registration_success',
    walletId,
    nearReadiness: 'ready',
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
      const ecdsa = requireThresholdEcdsaSessionFields(args);
      return {
        ecdsaTargetProfile: 'tempo_arc',
        thresholdEcdsaEthereumAddress: ecdsa.thresholdEcdsaEthereumAddress,
        thresholdEcdsaPublicKeyB64u: ecdsa.thresholdEcdsaPublicKeyB64u,
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
        thresholdEcdsaEthereumAddress: args.session.thresholdEcdsaEthereumAddress,
        thresholdEcdsaPublicKeyB64u: args.session.thresholdEcdsaPublicKeyB64u,
        ecdsaTargetKeys: args.ecdsaTargetKeys,
      };
    default:
      return assertNever(args.session);
  }
}

function registrationEcdsaTargetKeys(
  registration: IntendedEcdsaSessionSummary,
): IntendedEcdsaTargetKeysSummary {
  switch (registration.ecdsaTargetProfile) {
    case 'none':
      return { kind: 'none' };
    case 'tempo':
      return {
        kind: 'tempo',
        tempo: registrationEcdsaTargetKey('tempo', registration.thresholdEcdsaEthereumAddress),
      };
    case 'tempo_arc': {
      const thresholdOwnerAddress = registration.thresholdEcdsaEthereumAddress;
      return {
        kind: 'tempo_arc',
        tempo: registrationEcdsaTargetKey('tempo', thresholdOwnerAddress),
        arcEvm: registrationEcdsaTargetKey('arc_evm', thresholdOwnerAddress),
      };
    }
    default:
      return assertNever(registration);
  }
}

function registrationEcdsaTargetKey(
  chain: IntendedEcdsaTargetKeySummary['chain'],
  thresholdOwnerAddress: string,
): IntendedEcdsaTargetKeySummary {
  return {
    chain,
    chainId: intendedEcdsaChainTarget(chain).chainId,
    thresholdOwnerAddress,
  };
}

function assertEmailOtpRegistrationCompleted(args: {
  completed: {
    walletId: string;
    session: WalletSession;
    registration: RegistrationResult;
  };
  initialWalletId: string;
  ecdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
  nearProvisioning: IntendedNearProvisioningState | null;
}): EmailOtpRegistrationCoreSummary {
  const completed = args.completed;
  const walletId = String(completed.walletId || '').trim();
  if (!walletId) {
    throw new Error('Email OTP registration did not return walletId');
  }
  if (walletId === args.initialWalletId) {
    throw new Error('Email OTP registration reroll returned the initial walletId');
  }
  if (completed.session.appIdentity.kind !== 'resolved') {
    throw new Error(
      `Email OTP registration wallet identity is ${completed.session.appIdentity.kind}`,
    );
  }
  const sessionWalletId = String(completed.session.appIdentity.walletId).trim();
  if (sessionWalletId !== walletId) {
    throw new Error(`Email OTP registration session wallet mismatch: ${sessionWalletId}`);
  }
  const nearAccountId = String(completed.session.appIdentity.nearAccountId || '').trim();
  const operationalPublicKey = String(
    completed.session.appIdentity.nearOperationalPublicKey || '',
  ).trim();
  const ecdsa = assertEcdsaSessionSummary({
    ecdsaTargetProfile: args.ecdsaTargetProfile,
    source: registrationEcdsaCapability(completed.registration),
    label: 'Email OTP registration',
  });
  const reusableWalletSession = completed.session.reusableWalletSession;
  if (reusableWalletSession.kind !== 'active') {
    throw new Error(
      `Email OTP registration did not return an active signing session: ${reusableWalletSession.kind}`,
    );
  }
  const common = {
    kind: 'email_otp_registration_success' as const,
    initialWalletId: args.initialWalletId,
    walletId,
    signingSessionStatus: reusableWalletSession.kind,
    remainingUses: reusableWalletSession.remainingUses,
  };
  if (nearAccountId && operationalPublicKey) {
    return {
      ...common,
      nearReadiness: 'ready',
      nearAccountId,
      operationalPublicKey,
      ...ecdsa,
    };
  }
  /* No identity and no provisioning means this wallet's signer set never
     included Ed25519, which is a shape rather than a failure. */
  if (!args.nearProvisioning) {
    return { ...common, nearReadiness: 'absent', ...ecdsa };
  }
  return {
    ...common,
    nearReadiness: 'pending',
    nearProvisioning: nearProvisioningSummaryStatus(args.nearProvisioning),
    ...ecdsa,
  };
}

function registrationEcdsaCapability(result: RegistrationResult): EcdsaSessionFields {
  if (!result.success) {
    throw new Error(result.error || 'Email OTP registration failed');
  }
  if (result.kind === 'near_wallet_registered_pending') return {};
  for (const capability of result.capabilities) {
    if (capability.kind === 'evm_family_ecdsa') return capability;
  }
  return {};
}

function nearProvisioningSummaryStatus(
  state: IntendedNearProvisioningState,
): IntendedNearProvisioningSummary {
  switch (state.status) {
    case 'near_pending':
      return { status: 'pending' };
    case 'near_provisioning':
      return { status: 'provisioning' };
    case 'near_failed_retryable':
      return { status: 'retryable', error: state.error, errorCode: state.errorCode };
    case 'near_ready':
      throw new Error('NEAR readiness is missing its wallet session identity');
    default:
      return assertNever(state);
  }
}

async function awaitWalletNearReady(args: {
  registration: ReturnType<typeof useSeams>['seams']['registration'];
  walletId: string;
}): Promise<IntendedNearProvisioningReadyState> {
  const current = await args.registration.getNearProvisioningState({ walletId: args.walletId });
  const settled = settleNearProvisioningState(current);
  if (settled) return settled;

  return await new Promise<IntendedNearProvisioningReadyState>((resolve, reject) => {
    let unsubscribe = (): void => undefined;
    const timeout = window.setTimeout(() => {
      unsubscribe();
      reject(new Error('Timed out waiting for NEAR provisioning'));
    }, 120_000);
    const settle = (state: IntendedNearProvisioningState | null): void => {
      try {
        const ready = settleNearProvisioningState(state);
        if (!ready) return;
        window.clearTimeout(timeout);
        unsubscribe();
        resolve(ready);
      } catch (error) {
        window.clearTimeout(timeout);
        unsubscribe();
        reject(error);
      }
    };
    unsubscribe = args.registration.onNearProvisioningStateChanged(
      (event: NearProvisioningStateChangedEvent) => {
        if (String(event.walletId) === args.walletId) settle(event.state);
      },
    );
    void args.registration
      .getNearProvisioningState({ walletId: args.walletId })
      .then(settle)
      .catch(reject);
  });
}

function settleNearProvisioningState(
  state: IntendedNearProvisioningState | null,
): IntendedNearProvisioningReadyState | null {
  if (!state) return null;
  switch (state.status) {
    case 'near_pending':
    case 'near_provisioning':
      return null;
    case 'near_ready':
      return state;
    case 'near_failed_retryable':
      throw new Error(`NEAR provisioning is retryable (${state.errorCode}): ${state.error}`);
    default:
      return assertNever(state);
  }
}

function assertEmailOtpUnlockSucceeded(args: {
  result: {
    walletId: string;
    session: WalletSession;
  };
  expectedWalletId: string;
  ecdsaTargetProfile: IntendedEmailOtpEcdsaTargetProfile;
}): EmailOtpUnlockCoreSummary {
  const result = args.result;
  const walletId = String(result.walletId || '').trim();
  if (walletId !== args.expectedWalletId) {
    throw new Error(`Email OTP unlock wallet mismatch: ${walletId}`);
  }
  const appIdentity = result.session.appIdentity;
  if (appIdentity.kind !== 'resolved') {
    throw new Error(`Email OTP unlock did not resolve app identity: ${appIdentity.kind}`);
  }
  const sessionWalletId = String(appIdentity.walletId).trim();
  if (sessionWalletId !== walletId) {
    throw new Error(`Email OTP unlock session wallet mismatch: ${sessionWalletId}`);
  }
  const nearAccountId = String(appIdentity.nearAccountId || '').trim();
  if (!nearAccountId) {
    throw new Error('Email OTP unlock did not return a NEAR account id');
  }
  const operationalPublicKey = String(appIdentity.nearOperationalPublicKey || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Email OTP unlock did not return an operational public key');
  }
  const ecdsa = assertEcdsaSessionSummary({
    ecdsaTargetProfile: args.ecdsaTargetProfile,
    source: appIdentity,
    label: 'Email OTP unlock',
  });
  const reusableWalletSession = result.session.reusableWalletSession;
  if (reusableWalletSession.kind !== 'active') {
    throw new Error(
      `Email OTP unlock did not return an active signing session: ${reusableWalletSession.kind}`,
    );
  }
  return {
    kind: 'email_otp_unlock_success',
    walletId,
    nearAccountId,
    operationalPublicKey,
    signingSessionStatus: reusableWalletSession.kind,
    remainingUses: reusableWalletSession.remainingUses,
    ...ecdsa,
  };
}

function assertPasskeyUnlockSucceeded(
  result: Awaited<ReturnType<ReturnType<typeof useSeams>['seams']['auth']['unlock']>>,
  expectedWalletId: string,
  sessionWalletAuthMethodId: string | null,
): PasskeyUnlockResultSummary {
  if (!result.success) {
    throw new Error(result.error || 'Passkey unlock failed');
  }
  const nearAccountId = String(result.nearAccountId || '').trim();
  const operationalPublicKey = String(result.operationalPublicKey || '').trim();
  const signingSessionStatus = String(result.signingSession?.status || '').trim();
  if (signingSessionStatus !== 'active') {
    throw new Error(
      `Passkey unlock did not return an active signing session: ${signingSessionStatus}`,
    );
  }
  const common = {
    kind: 'passkey_unlock_success' as const,
    walletId: expectedWalletId,
    sessionWalletAuthMethodId,
    signingSessionStatus,
    remainingUses: normalizeOptionalNumber(result.signingSession?.remainingUses),
  };
  if (nearAccountId && operationalPublicKey) {
    return {
      ...common,
      nearIdentity: 'ready',
      nearAccountId,
      operationalPublicKey,
    };
  }
  if (!nearAccountId && !operationalPublicKey) {
    return {
      ...common,
      nearIdentity: 'absent',
    };
  }
  throw new Error('Passkey unlock returned an incomplete NEAR identity');
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

function emailOtpDevOutboxUrl(input: { relayerUrl: string }): string {
  return new URL('/wallet/email-otp/dev/otp-outbox', input.relayerUrl).href;
}

/**
 * The subject the dev outbox should read, when it is not the Google identity.
 *
 * Module scope, not controller state: the controller is rebuilt on every
 * render, so the instance the page installed on `window` is not necessarily
 * the one an action mutated. Only an addition by address sets this; every
 * other flow's challenges belong to the Google subject the id token carries,
 * and overriding them would make those unreadable.
 */
let intendedEmailOtpChallengeSubjectOverride: string | null = null;

/**
 * The address an added Email OTP method enrols under in this harness.
 *
 * Derived from the wallet so repeated runs against a persistent local stack do
 * not fight over one provider identity, and shared by the action and the dev
 * outbox reader so both name the same subject.
 */
function intendedAddEmailOtpAddress(walletId: string): string {
  return `add-auth-${walletId.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}@example.test`;
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
  window.__seamsIntendedE2ELockWallet = controller.lockWalletForIntendedTest;
  window.__seamsIntendedE2EReadWalletLockState = controller.readWalletLockStateForIntendedTest;
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
