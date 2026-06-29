import type { RegistrationSignerSetSelection } from '@shared/utils/registrationIntent';

export type RegistrationSignerSetRequest = RegistrationSignerSetSelection;

export function registrationSignerSetRequestSelection(
  selection: RegistrationSignerSetRequest,
): RegistrationSignerSetSelection {
  return selection;
}
