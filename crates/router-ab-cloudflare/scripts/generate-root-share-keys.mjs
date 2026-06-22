import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2).filter((arg) => arg !== '--');
const json = argv.includes('--json');
const repoRoot = resolve(new URL('../../..', import.meta.url).pathname);
const thresholdPrfPath = join(repoRoot, 'crates/threshold-prf');

if (argv.includes('--help')) {
  console.log(`Usage:
  pnpm router:deploy:root-share-keygen
  pnpm router:deploy:root-share-keygen -- --json

Generates a matched Router A/B MPC PRF root-share pair.
Store SIGNER_A_ROOT_SHARE_WIRE_SECRET only in the Account-1 environment.
Store SIGNER_B_ROOT_SHARE_WIRE_SECRET only in the Account-2 / Deriver-B environment.`);
  process.exit(0);
}

const tempDir = mkdtempSync(join(tmpdir(), 'router-ab-root-share-keygen-'));

try {
  writeFileSync(join(tempDir, 'Cargo.toml'), cargoToml(thresholdPrfPath));
  const srcDir = join(tempDir, 'src');
  spawn('mkdir', ['-p', srcDir]);
  writeFileSync(join(srcDir, 'main.rs'), rustMain());

  const child = spawnSync('cargo', ['run', '--quiet', '--manifest-path', join(tempDir, 'Cargo.toml')], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  if (child.status !== 0) {
    process.stderr.write(child.stderr || child.stdout || 'root-share keygen failed\n');
    process.exit(child.status ?? 1);
  }

  const result = JSON.parse(child.stdout);
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanOutput(result);
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

function cargoToml(path) {
  return `[package]
name = "router-ab-root-share-keygen"
version = "0.1.0"
edition = "2021"

[dependencies]
threshold-prf = { path = ${JSON.stringify(path)} }
rand_core = { version = "0.6.4", features = ["getrandom"] }
serde_json = "1.0"
`;
}

function rustMain() {
  return String.raw`use rand_core::OsRng;
use serde_json::json;
use threshold_prf::{
    generate_signing_root, split_signing_root, SigningRootShareWire, ThresholdPolicy,
};

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{:02x}", byte).expect("hex write");
    }
    out
}

fn main() {
    let mut rng = OsRng;
    let root = generate_signing_root(&mut rng);
    let policy = ThresholdPolicy::from_u16s(2, 3).expect("2-of-3 policy");
    let shares = split_signing_root(&root, policy, &mut rng).expect("split signing root");
    let share_a = SigningRootShareWire::from_share(&shares[0]).to_bytes();
    let share_b = SigningRootShareWire::from_share(&shares[2]).to_bytes();

    println!(
        "{}",
        json!({
            "generatedAt": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_millis(),
            "policy": {
                "threshold": 2,
                "shareCount": 3,
                "deriverAShareId": 1,
                "deriverBShareId": 3,
            },
            "secrets": {
                "account1DeriverA": {
                    "SIGNER_A_ROOT_SHARE_WIRE_SECRET": format!(
                        "mpc-prf-root-share-wire-v1:{}",
                        lower_hex(&share_a)
                    )
                },
                "account2DeriverB": {
                    "SIGNER_B_ROOT_SHARE_WIRE_SECRET": format!(
                        "mpc-prf-root-share-wire-v1:{}",
                        lower_hex(&share_b)
                    )
                }
            }
        })
    );
}
`;
}

function printHumanOutput(result) {
  console.log('Router A/B root-share wire secrets');
  console.log(`Generated at epoch ms: ${result.generatedAt}`);
  console.log(
    `Policy: ${result.policy.threshold}-of-${result.policy.shareCount}; Deriver A share ${result.policy.deriverAShareId}; Deriver B share ${result.policy.deriverBShareId}`,
  );
  console.log('\nAccount 1 / Deriver A secret:');
  console.log(
    `SIGNER_A_ROOT_SHARE_WIRE_SECRET=${result.secrets.account1DeriverA.SIGNER_A_ROOT_SHARE_WIRE_SECRET}`,
  );
  console.log('\nAccount 2 / Deriver B secret:');
  console.log(
    `SIGNER_B_ROOT_SHARE_WIRE_SECRET=${result.secrets.account2DeriverB.SIGNER_B_ROOT_SHARE_WIRE_SECRET}`,
  );
  console.log('\nStore these as a pair. Do not copy A into Account 2 or B into Account 1.');
}

function spawn(command, args) {
  const child = spawnSync(command, args, { stdio: 'inherit' });
  if (child.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed`);
  }
}
