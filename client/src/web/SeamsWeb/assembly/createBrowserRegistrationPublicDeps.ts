import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import type { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';

type SigningEnginePorts = ReturnType<typeof createSigningEnginePorts>;

export function createBrowserRegistrationPublicDeps(args: {
  enginePorts: Pick<
    SigningEnginePorts,
    'registrationAccountLifecycleDeps' | 'registrationSessionDeps' | 'nearKeyOpsDeps'
  >;
}): registrationPublic.RegistrationPublicDeps {
  return {
    accountLifecycle: args.enginePorts.registrationAccountLifecycleDeps,
    session: args.enginePorts.registrationSessionDeps,
    signingKeyOps: args.enginePorts.nearKeyOpsDeps.signingKeyOps,
  };
}
