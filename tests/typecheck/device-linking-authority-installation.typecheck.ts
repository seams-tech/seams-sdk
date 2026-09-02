import type { ActivateInstalledAuthorityResultV1 } from '../../packages/shared-ts/src/device-linking/contracts';
import type { DeviceLinkingAuthorityInstallationPortV1 } from '../../packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation';

declare const installation: DeviceLinkingAuthorityInstallationPortV1;
declare const activation: ActivateInstalledAuthorityResultV1;

if (activation.kind === 'active') {
  void installation.finalizeLocalAuthorityActivationV1({
    active: activation,
    expectedLockGeneration: 0,
  });
  // @ts-expect-error Finalization must carry the generation captured before installation.
  void installation.finalizeLocalAuthorityActivationV1({ active: activation });
} else {
  // @ts-expect-error Pending and integrity results cannot finalize local authority state.
  void installation.finalizeLocalAuthorityActivationV1(activation);
}
