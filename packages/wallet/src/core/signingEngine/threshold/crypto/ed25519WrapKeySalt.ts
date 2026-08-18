import { base64UrlEncode } from '@shared/utils/encoders';

export const THRESHOLD_ED25519_WRAP_KEY_SALT_B64U = base64UrlEncode(new Uint8Array(32));
