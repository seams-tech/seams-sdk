import {
  type RouterAbEd25519YaoExportSeedInputV1,
  WasmRouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoRegistrationTransportRequestV1,
} from './yaoClient';

declare const admitRequest: Extract<
  RouterAbEd25519YaoRegistrationTransportRequestV1,
  { kind: 'admit' }
>['body'];
declare const executeRequest: Extract<
  RouterAbEd25519YaoRegistrationTransportRequestV1,
  { kind: 'execute' }
>['body'];

const validAdmitTransportRequest = {
  kind: 'admit',
  path: '/router-ab/ed25519/yao/registration/admit',
  body: admitRequest,
} satisfies RouterAbEd25519YaoRegistrationTransportRequestV1;

void validAdmitTransportRequest;
void executeRequest;

// @ts-expect-error An execute body cannot cross the admission transport branch.
const mismatchedTransportRequest: RouterAbEd25519YaoRegistrationTransportRequestV1 = {
  kind: 'admit',
  path: '/router-ab/ed25519/yao/registration/admit',
  body: executeRequest,
};

void mismatchedTransportRequest;

// @ts-expect-error Active Client state can only be created from verified WASM completion.
const forgedActiveClient = new WasmRouterAbEd25519YaoActiveClientV1({});

void forgedActiveClient;

declare const exportRequest: RouterAbEd25519YaoExportSeedInputV1['request'];
declare const exportTransport: RouterAbEd25519YaoExportSeedInputV1['transport'];
declare const passkeyFactor: Extract<
  RouterAbEd25519YaoExportSeedInputV1,
  { factor: { kind: 'passkey_prf_first' } }
>['factor'];
declare const emailOtpFactor: Extract<
  RouterAbEd25519YaoExportSeedInputV1,
  { factor: { kind: 'email_otp_factor' } }
>['factor'];
declare const passkeyAuthorization: Extract<
  RouterAbEd25519YaoExportSeedInputV1,
  { factor: { kind: 'passkey_prf_first' } }
>['authorization'];
declare const emailOtpAuthorization: Extract<
  RouterAbEd25519YaoExportSeedInputV1,
  { factor: { kind: 'email_otp_factor' } }
>['authorization'];

const validPasskeyExport = {
  request: exportRequest,
  transport: exportTransport,
  factor: passkeyFactor,
  authorization: passkeyAuthorization,
} satisfies RouterAbEd25519YaoExportSeedInputV1;

const validEmailOtpExport = {
  request: exportRequest,
  transport: exportTransport,
  factor: emailOtpFactor,
  authorization: emailOtpAuthorization,
} satisfies RouterAbEd25519YaoExportSeedInputV1;

void validPasskeyExport;
void validEmailOtpExport;

// @ts-expect-error A passkey root cannot be paired with Email OTP authorization.
const mismatchedPasskeyExport: RouterAbEd25519YaoExportSeedInputV1 = {
  request: exportRequest,
  transport: exportTransport,
  factor: passkeyFactor,
  authorization: emailOtpAuthorization,
};

// @ts-expect-error An Email OTP root cannot be paired with passkey authorization.
const mismatchedEmailOtpExport: RouterAbEd25519YaoExportSeedInputV1 = {
  request: exportRequest,
  transport: exportTransport,
  factor: emailOtpFactor,
  authorization: passkeyAuthorization,
};

void mismatchedPasskeyExport;
void mismatchedEmailOtpExport;
