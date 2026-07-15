import type { ExactEd25519SigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { Ed25519YaoExportFlowDeps } from './ed25519YaoExportFlow';

type PasskeyEd25519Lane = ExactEd25519SigningLaneIdentity & {
  auth: Extract<ExactEd25519SigningLaneIdentity['auth'], { kind: 'passkey' }>;
};

type EmailOtpEd25519Lane = ExactEd25519SigningLaneIdentity & {
  auth: Extract<ExactEd25519SigningLaneIdentity['auth'], { kind: 'email_otp' }>;
};

declare const deps: Ed25519YaoExportFlowDeps;
declare const passkeyLane: PasskeyEd25519Lane;
declare const emailOtpLane: EmailOtpEd25519Lane;

void deps.recoverPasskeyCapability(passkeyLane);

// @ts-expect-error Email OTP export resolves durable context and cannot enter passkey recovery.
void deps.recoverPasskeyCapability(emailOtpLane);
