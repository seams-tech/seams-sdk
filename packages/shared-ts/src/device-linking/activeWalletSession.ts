import type { ActiveWalletSessionV1 } from './contracts';
import { mpcMaterialActivationRefsEqual } from '../utils/domainIds';

export function activeWalletSessionV1RecordsEqual(
  left: ActiveWalletSessionV1,
  right: ActiveWalletSessionV1,
): boolean {
  if (
    left.kind !== right.kind ||
    left.walletId !== right.walletId ||
    left.authorityId !== right.authorityId ||
    left.authMethodId !== right.authMethodId ||
    left.authorizationId !== right.authorizationId ||
    left.quotaId !== right.quotaId ||
    left.authorityDigestB64u !== right.authorityDigestB64u ||
    left.authorityRevocationEpoch !== right.authorityRevocationEpoch ||
    left.issuedAtMs !== right.issuedAtMs ||
    left.expiresAtMs !== right.expiresAtMs ||
    left.capabilitySubjects.length !== right.capabilitySubjects.length
  ) {
    return false;
  }
  for (let index = 0; index < left.capabilitySubjects.length; index += 1) {
    const leftSubject = left.capabilitySubjects[index];
    const rightSubject = right.capabilitySubjects[index];
    if (!leftSubject || !rightSubject || leftSubject.kind !== rightSubject.kind) return false;
    switch (leftSubject.kind) {
      case 'sign':
      case 'export_keys':
        if (
          rightSubject.kind !== leftSubject.kind ||
          rightSubject.keyFamily !== leftSubject.keyFamily ||
          !mpcMaterialActivationRefsEqual(
            leftSubject.materialActivation,
            rightSubject.materialActivation,
          )
        ) {
          return false;
        }
        break;
      case 'link_devices':
      case 'revoke_devices':
        if (rightSubject.kind !== leftSubject.kind) return false;
        break;
      default:
        leftSubject satisfies never;
        return false;
    }
  }
  return true;
}
