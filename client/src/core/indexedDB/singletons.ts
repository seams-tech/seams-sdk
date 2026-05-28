import { SeamsWalletDBManager } from './seamsWalletDB/manager';

// Shared singleton instances used by runtime/config wiring.
export const seamsWalletDB = new SeamsWalletDBManager();
