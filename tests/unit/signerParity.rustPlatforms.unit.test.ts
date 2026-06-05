import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const parityFeatures = 'secp256k1,near-crypto,near-threshold-ed25519,tx-finalization';

type ParityCommand = {
  label: string;
  command: string;
  args: string[];
};

const rustParityCommands: ParityCommand[] = [
  {
    label: 'signer-core eip1559 tx-finalization vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-core/Cargo.toml',
      '--locked',
      '--features',
      'tx-finalization',
      'eip1559_vectors_are_stable',
    ],
  },
  {
    label: 'signer-core tempo tx-finalization vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-core/Cargo.toml',
      '--locked',
      '--features',
      'tx-finalization',
      'tempo_vectors_are_stable',
    ],
  },
  {
    label: 'signer-core baseline vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-core/Cargo.toml',
      '--locked',
      '--features',
      parityFeatures,
      'vectors_v1_match_expected_outputs',
    ],
  },
  {
    label: 'signer-wasm-core baseline vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-wasm-core/Cargo.toml',
      '--locked',
      '--features',
      parityFeatures,
      'vectors_v1_match_expected_outputs',
    ],
  },
  {
    label: 'signer-wasm-core invalid tx-finalization vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-wasm-core/Cargo.toml',
      '--locked',
      '--features',
      parityFeatures,
      'invalid_tx_finalization_vectors_match_expected_errors',
    ],
  },
  {
    label: 'signer-embedded-linux baseline vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-embedded-linux/Cargo.toml',
      '--locked',
      '--features',
      parityFeatures,
      'vectors_v1_match_expected_outputs',
    ],
  },
  {
    label: 'signer-embedded-linux invalid tx-finalization vectors',
    command: 'cargo',
    args: [
      'test',
      '--manifest-path',
      'crates/signer-embedded-linux/Cargo.toml',
      '--locked',
      '--features',
      parityFeatures,
      'invalid_tx_finalization_vectors_match_expected_errors',
    ],
  },
];

function tail(text: string, maxChars = 6000): string {
  if (text.length <= maxChars) return text;
  return text.slice(text.length - maxChars);
}

function runParityCommand(step: ParityCommand): void {
  const result = spawnSync(step.command, step.args, {
    cwd: repoRoot,
    env: process.env,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
  });

  if (result.status === 0) return;

  const status = result.error ? `error: ${result.error.message}` : `exit code ${result.status}`;
  throw new Error(
    `[signer-parity] ${step.label} failed (${status})\n` +
      `stdout:\n${tail(String(result.stdout || ''))}\n` +
      `stderr:\n${tail(String(result.stderr || ''))}`,
  );
}

test.describe.configure({ mode: 'serial' });

test.describe('signer parity rust surfaces', () => {
  for (const step of rustParityCommands) {
    test(step.label, async () => {
      test.setTimeout(20 * 60 * 1000);
      runParityCommand(step);
    });
  }
});
