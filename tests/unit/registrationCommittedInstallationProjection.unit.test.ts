import { expect, test } from '@playwright/test';
import { parseD1WalletRegistrationCommittedInstallationProjection } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords';
import {
  buildRegistrationCommittedInstallationProjectionFixture,
  REGISTRATION_COMMITTED_INSTALLATION_PROJECTION_FIXTURE_IDS,
} from './helpers/registrationCommittedInstallationProjection.fixtures';

const { registrationCeremonyId: REGISTRATION_CEREMONY_ID } =
  REGISTRATION_COMMITTED_INSTALLATION_PROJECTION_FIXTURE_IDS;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

test('strictly parses a credential-free mixed installation projection', () => {
  const parsed = parseD1WalletRegistrationCommittedInstallationProjection(
    buildRegistrationCommittedInstallationProjectionFixture(),
  );

  expect(parsed).not.toBeNull();
  expect(parsed?.registrationCeremonyId).toBe(REGISTRATION_CEREMONY_ID);
  expect(parsed?.preparedContext.ecdsa.kind).toBe('evm_family_ecdsa_requested');
});

test('rejects projection records with unknown nested fields or mismatched NEAR scope', () => {
  const withAuthorityExtra = buildRegistrationCommittedInstallationProjectionFixture();
  const authority = withAuthorityExtra.registrationAuthority;
  if (!isRecord(authority)) throw new Error('projection fixture authority is not an object');
  withAuthorityExtra.registrationAuthority = { ...authority, walletSessionToken: 'forbidden' };
  expect(parseD1WalletRegistrationCommittedInstallationProjection(withAuthorityExtra)).toBeNull();

  const withNearScopeMismatch = buildRegistrationCommittedInstallationProjectionFixture();
  const near = withNearScopeMismatch.nearEd25519;
  if (!isRecord(near)) throw new Error('projection fixture NEAR branch is not an object');
  const admissionRequest = near.admissionRequest;
  if (!isRecord(admissionRequest))
    throw new Error('projection fixture admission request is not an object');
  const scope = admissionRequest.scope;
  if (!isRecord(scope)) throw new Error('projection fixture admission scope is not an object');
  admissionRequest.scope = { ...scope, signer_set_id: 'near_ed25519:slot:9' };
  expect(
    parseD1WalletRegistrationCommittedInstallationProjection(withNearScopeMismatch),
  ).toBeNull();
});
