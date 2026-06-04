import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  EmailOtpPublicDeps,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';

export function createBrowserEmailOtpPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  warmSigning: WarmSigningPorts;
  getSignerWorkerContext: EmailOtpPublicDeps['getSignerWorkerContext'];
  emailOtpSessions: EmailOtpThresholdSessionCoordinator;
}): EmailOtpPublicDeps {
  return {
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    relayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
    shamirPrimeB64u: args.seamsWebConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
    getSignerWorkerContext: args.getSignerWorkerContext,
    emailOtpSessions: args.emailOtpSessions,
  };
}
