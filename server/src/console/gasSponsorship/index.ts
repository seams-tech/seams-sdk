export type {
  ConsoleGasSponsorshipScopeType,
  ConsoleGasSponsorshipNetworkClass,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipSpendCapMode,
  ConsoleGasSponsorshipSpendCapPeriod,
  ConsoleGasSponsorshipSpendCapChain,
  ConsoleGasSponsorshipSpendCap,
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipTelemetry,
  ConsoleGasSponsorshipPolicyProjection,
} from './types';

export {
  projectConsoleGasSponsorshipPolicyProjection,
  sortConsoleGasSponsorshipPolicyProjections,
} from './service';

export type { ResolvedSponsoredCallPolicy } from './onboarding';
export {
  TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
  TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
  TEMPO_TESTNET_CHAIN_ID,
  TEMPO_DRIP_SELECTOR,
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  buildTempoTestnetOnboardingGasPolicyRules,
  ensureTempoTestnetOnboardingPolicyForEnvironment,
  resolveSponsoredCallPoliciesFromProjections,
} from './onboarding';
export {
  createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship,
  ensureTempoOnboardingSponsorshipForExistingEnvironments,
} from './seeding';

export { ConsoleGasSponsorshipError, isConsoleGasSponsorshipError } from './errors';
