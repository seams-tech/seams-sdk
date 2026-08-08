import type {
  HostedAuthMenuCopy,
  HostedAuthMenuCopyInput,
  HostedAuthMenuExternalAuthEvidence,
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuDemoEmailOtpDelivery,
  HostedAuthMenuExternalProvider,
  HostedAuthMenuMode,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuRegistrationAccountInput,
  HostedAuthMenuSessionId,
} from '@/SeamsWeb/walletIframe/shared/messages';

export type {
  HostedAuthMenuCopy,
  HostedAuthMenuCopyInput,
  HostedAuthMenuExternalAuthEvidence,
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuDemoEmailOtpDelivery,
  HostedAuthMenuExternalProvider,
  HostedAuthMenuMode,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuRegistrationAccountInput,
  HostedAuthMenuSessionId,
};

export type SeamsAuthMenuMode = HostedAuthMenuMode;
export type SeamsAuthMenuRegistrationAccountInput = HostedAuthMenuRegistrationAccountInput;
export type SeamsAuthMenuCopy = HostedAuthMenuCopyInput;

/**
 * Acquires app-origin evidence for a provider interaction requested by the wallet host.
 * The request carries the exact session and provider-request identities from the iframe.
 */
export type HostedAuthMenuExternalAuthBroker = (
  request: HostedAuthMenuExternalAuthRequest,
) => HostedAuthMenuExternalAuthEvidence | Promise<HostedAuthMenuExternalAuthEvidence>;

export type SeamsAuthMenuOutcomeHandler = (outcome: HostedAuthMenuOutcome) => void;
export type HostedAuthMenuDemoEmailOtpHandler = (
  delivery: HostedAuthMenuDemoEmailOtpDelivery['delivery'],
) => void;

export interface HostedSeamsAuthMenuProps {
  /** Initial view selected by the wallet-host menu. Defaults to login. */
  initialMode?: SeamsAuthMenuMode;
  /** Wallet/account policy used by registration. Defaults to implicit wallet. */
  registrationAccountInput?: SeamsAuthMenuRegistrationAccountInput;
  /** Whether the wallet-host registration view exposes its account input. */
  showRegistrationInput?: boolean;
  /** Whether the wallet-host surface displays SDK operation progress. Defaults to false. */
  showProgress?: boolean;
  /** Serializable copy overrides normalized before crossing the iframe boundary. */
  copy?: HostedAuthMenuCopyInput;
  /** App-origin provider broker, or null when no external provider is enabled. */
  externalAuthBroker?: HostedAuthMenuExternalAuthBroker | null;
  /** Receives demo Email OTP delivery from the wallet origin. */
  onDemoEmailOtp?: HostedAuthMenuDemoEmailOtpHandler;
  /** Receives exactly one terminal outcome for each mounted session. */
  onOutcome: SeamsAuthMenuOutcomeHandler;
}
