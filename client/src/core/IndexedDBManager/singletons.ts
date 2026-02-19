import { PasskeyClientDBManager } from './passkeyClientDB/manager';
import { PasskeyNearKeysDBManager } from './passkeyNearKeysDB/manager';

// Shared singleton instances used by runtime/config wiring.
export const passkeyClientDB = new PasskeyClientDBManager();
export const passkeyNearKeysDB = new PasskeyNearKeysDBManager();
