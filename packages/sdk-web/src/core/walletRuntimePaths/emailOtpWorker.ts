import { resolveWorkerBaseOrigin } from './workers';

export function resolveEmailOtpWorkerUrl(opts?: { baseOrigin?: string }): string {
  const baseOrigin =
    opts?.baseOrigin ||
    resolveWorkerBaseOrigin() ||
    (typeof window !== 'undefined' ? window.location.origin : '') ||
    'https://invalid.local';

  const override =
    typeof window !== 'undefined' &&
    typeof (window as { __W3A_EMAIL_OTP_WORKER_URL__?: unknown }).__W3A_EMAIL_OTP_WORKER_URL__ ===
      'string'
      ? String((window as { __W3A_EMAIL_OTP_WORKER_URL__?: string }).__W3A_EMAIL_OTP_WORKER_URL__)
      : '';
  const candidate = override || '/sdk/workers/email-otp.worker.js';
  if (/^https?:\/\//i.test(candidate)) return candidate;
  return new URL(candidate, baseOrigin).toString();
}
