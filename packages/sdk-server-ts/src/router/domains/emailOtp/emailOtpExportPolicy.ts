import type {
  RouterApiEmailOtpExportPolicyDecision,
  RouterApiEmailOtpExportPolicyInput,
  RouterApiOptions,
} from './routerApi';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';

export type ResolvedEmailOtpExportPolicyDecision = RouterApiEmailOtpExportPolicyDecision & {
  policySource: 'adapter' | 'default_allow';
};

export async function authorizeEmailOtpExportPolicy(
  opts: RouterApiOptions,
  input: RouterApiEmailOtpExportPolicyInput,
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
  source: 'login_challenge' | 'login_verify' | 'signing_session_challenge' | 'signing_session_verify';
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

export function emailOtpExportPolicyWebhookEventDescriptor(input: {
  eventType:
    | 'wallet.email_otp.export_denied'
    | 'wallet.email_otp.export_challenge_issued'
    | 'wallet.email_otp.export_approved';
  source: 'login_challenge' | 'login_verify' | 'signing_session_challenge' | 'signing_session_verify';
  decision: ResolvedEmailOtpExportPolicyDecision;
  challengeId?: string;
  otpChannel?: string;
  code?: string;
  message?: string;
}): {
  eventType: string;
  eventId?: string;
  payload: Record<string, unknown>;
} {
  return {
    eventType: input.eventType,
    ...(input.challengeId ? { eventId: input.challengeId } : {}),
    payload: {
      ...emailOtpExportPolicyAuditPayload({
        source: input.source,
        decision: input.decision,
        ...(input.challengeId ? { challengeId: input.challengeId } : {}),
        ...(input.otpChannel ? { otpChannel: input.otpChannel } : {}),
      }),
      ...(input.code ? { code: input.code } : {}),
      ...(input.message ? { message: input.message } : {}),
    },
  };
}

export function emailOtpExportDeniedDecisionFromResult(input: {
  code: string;
  message: string;
  policySource: ResolvedEmailOtpExportPolicyDecision['policySource'];
  policyId?: string;
  approvalId?: string;
}): ResolvedEmailOtpExportPolicyDecision {
  return {
    ok: false,
    decision: 'DENY',
    code: input.code,
    message: input.message,
    policySource: input.policySource,
    ...(input.policyId ? { policyId: input.policyId } : {}),
    ...(input.approvalId ? { approvalId: input.approvalId } : {}),
  };
}
