import type {
  RelayEmailOtpExportPolicyDecision,
  RelayEmailOtpExportPolicyInput,
  RelayRouterOptions,
} from './relay';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';

export type ResolvedEmailOtpExportPolicyDecision = RelayEmailOtpExportPolicyDecision & {
  policySource: 'adapter' | 'default_allow';
};

export async function authorizeEmailOtpExportPolicy(
  opts: RelayRouterOptions,
  input: RelayEmailOtpExportPolicyInput,
): Promise<ResolvedEmailOtpExportPolicyDecision> {
  const adapter = opts.emailOtpExportPolicy;
  if (!adapter) {
    return {
      ok: true,
      decision: 'ALLOW',
      policyId: 'default-email-otp-export-policy',
      reason: `No Email OTP export policy adapter configured; local default allows ${WALLET_EMAIL_OTP_EXPORT_OPERATION}.`,
      policySource: 'default_allow',
    };
  }

  const decision = await adapter.authorize(input);
  if (decision.ok) {
    return {
      ...decision,
      decision: 'ALLOW',
      policySource: 'adapter',
    };
  }
  return {
    ...decision,
    decision: 'DENY',
    code: String(decision.code || '').trim() || 'export_key_policy_denied',
    message: String(decision.message || '').trim() || 'Email OTP key export denied by policy',
    policySource: 'adapter',
  };
}

export function emailOtpExportPolicyAuditPayload(input: {
  source: 'login_challenge' | 'login_verify';
  decision: ResolvedEmailOtpExportPolicyDecision;
  challengeId?: string;
  otpChannel?: string;
}): Record<string, unknown> {
  const decision = input.decision;
  return {
    source: input.source,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    policyDecision: decision.decision,
    policySource: decision.policySource,
    ...(decision.policyId ? { policyId: decision.policyId } : {}),
    ...(decision.approvalId ? { approvalId: decision.approvalId } : {}),
    ...(decision.reason ? { reason: decision.reason } : {}),
    ...(input.challengeId ? { challengeId: input.challengeId } : {}),
    ...(input.otpChannel ? { otpChannel: input.otpChannel } : {}),
  };
}
