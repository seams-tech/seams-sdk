import { PasskeyClientDBManager } from './passkeyClientDB/manager';
import { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';

// Shared singleton instances used by runtime/config wiring.
export const passkeyClientDB = new PasskeyClientDBManager();
export const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
