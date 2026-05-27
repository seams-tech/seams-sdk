import { PasskeyClientDBManager } from './passkeyClientDB/manager';
import { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
import { SeamsWalletDBManager } from './seamsWalletDB/manager';

// Shared singleton instances used by runtime/config wiring.
export const passkeyClientDB = new PasskeyClientDBManager();
export const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
export const seamsWalletDB = new SeamsWalletDBManager();
