import type { ExactEd25519ExportMaterialIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { Ed25519YaoExportFlowDeps } from './ed25519YaoExportFlow';

type PasskeyEd25519Lane = ExactEd25519ExportMaterialIdentity & {
  auth: Extract<ExactEd25519ExportMaterialIdentity['auth'], { kind: 'passkey' }>;
};

type EmailOtpEd25519Lane = ExactEd25519ExportMaterialIdentity & {
  auth: Extract<ExactEd25519ExportMaterialIdentity['auth'], { kind: 'email_otp' }>;
};

declare const deps: Ed25519YaoExportFlowDeps;
declare const passkeyLane: PasskeyEd25519Lane;
declare const emailOtpLane: EmailOtpEd25519Lane;

declare const materialActivation: Parameters<
  Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']
>[0]['materialActivation'];
void deps.resolvePasskeyExportContext({ laneIdentity: passkeyLane, materialActivation });

// @ts-expect-error Email OTP export resolves through its factor-owned context boundary.
void deps.resolvePasskeyExportContext({ laneIdentity: emailOtpLane, materialActivation });
