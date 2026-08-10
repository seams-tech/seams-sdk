import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/registrationPendingFinalization';
import { routerAbEcdsaRegistrationPendingFinalizationFixture } from './helpers/routerAbEcdsaRegistrationPendingFinalization.fixtures';

function encodeRawCanonicalJson(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(alphabetizeStringify(value)));
}

function decodePayload(encoded: string): unknown {
  return decodeRouterAbEcdsaRegistrationPendingFinalizationV1(encoded);
}

test('round trips the exact worker-owned registration pending-finalization payload', () => {
  const fixture = routerAbEcdsaRegistrationPendingFinalizationFixture();
  const decoded = decodeRouterAbEcdsaRegistrationPendingFinalizationV1(fixture.encoded);

  expect(decoded).toEqual(fixture.payload);
  expect(encodeRouterAbEcdsaRegistrationPendingFinalizationV1(decoded)).toBe(fixture.encoded);
});

test('rejects missing and extra pending-finalization fields', () => {
  const fixture = routerAbEcdsaRegistrationPendingFinalizationFixture();
  const { clientActivation: _clientActivation, ...missingClientActivation } = fixture.payload;
  const withExtraField = {
    ...fixture.payload,
    registrationCeremonyId: 'legacy-ceremony-alias',
  };

  expect(decodePayload.bind(undefined, encodeRawCanonicalJson(missingClientActivation))).toThrow(
    /invalid field set/,
  );
  expect(decodePayload.bind(undefined, encodeRawCanonicalJson(withExtraField))).toThrow(
    /invalid field set/,
  );
});

test('rejects mutated protocol facts', () => {
  const fixture = routerAbEcdsaRegistrationPendingFinalizationFixture();
  const mismatchedLifecycle = {
    ...fixture.payload,
    registrationRequest: {
      ...fixture.payload.registrationRequest,
      lifecycle: {
        ...fixture.payload.registrationRequest.lifecycle,
        lifecycle_id: 'mutated-registration-lifecycle',
      },
    },
  };
  expect(decodePayload.bind(undefined, encodeRawCanonicalJson(mismatchedLifecycle))).toThrow(
    /facts do not match/,
  );
});

test('rejects non-canonical JSON and base64url encodings', () => {
  const fixture = routerAbEcdsaRegistrationPendingFinalizationFixture();
  const canonicalJson = new TextDecoder().decode(base64UrlDecode(fixture.encoded));
  const nonCanonicalJson = `${canonicalJson}\n`;

  expect(
    decodePayload.bind(undefined, base64UrlEncode(new TextEncoder().encode(nonCanonicalJson))),
  ).toThrow(/canonical JSON/);
  expect(decodePayload.bind(undefined, `${fixture.encoded}=`)).toThrow(/unpadded base64url/);
});
