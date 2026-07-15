import { readdir, readFile } from 'node:fs/promises';
import { dirname, extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const voiceIdRoot = dirname(dirname(scriptPath));
const scannedRoots = ['README.md', 'docs', 'deploy', 'shared', 'client', 'server'];
const activeRoots = ['shared', 'client', 'server', 'demo', 'tests', 'verifier'];
const scannedExtensions = new Set(['.md', '.mjs', '.py', '.ts', '.tsx', '.json']);
const ignoredDirectories = new Set(['node_modules', '.cache', '__pycache__', 'fixtures']);

const forbidden = [
  { name: 'obsolete reserved authorization type', pattern: /ReservedVoiceIdR1Grant/ },
  { name: 'obsolete authorization record', pattern: /VoiceIdSigningGrant/ },
  { name: 'obsolete signing-candidate evidence', pattern: /VoiceIdSigningCandidateEvidence/ },
  { name: 'obsolete SDK signing continuation', pattern: /requestR1Signing/ },
  { name: 'deleted Router policy issuer document', pattern: /voiceId-router-policy-issuer\.md/ },
  { name: 'deleted duplicate biometrics design', pattern: /voice-biometrics\.md/ },
  { name: 'deleted duplicate UI plan', pattern: /voiceID-UI\.md/ },
  { name: 'deleted speculative camera plan', pattern: /voiceId-camera-liveness-future\.md/ },
  { name: 'deleted MVP 2 plan', pattern: /voiceId-mvp-2\.md/ },
  { name: 'deleted SDK signing plan', pattern: /voiceId-normal-sdk-transaction-signing\.md/ },
  { name: 'deleted SDK auth integration plan', pattern: /voiceId-sdk-auth-method-integration\.md/ },
  { name: 'deleted duplicate authenticator plan', pattern: /voiceId-user-verifying-authenticator-plan\.md/ },
  { name: 'server evidence risk admission', pattern: /server R1 policy/i },
  { name: 'server-issued voice authorization', pattern: /one-use (?:signing )?grant/i },
  { name: 'evidence authorization reservation', pattern: /grant reservation/i },
  { name: 'evidence signing candidate', pattern: /E2[^\n]{0,80}signing candidate/i },
];

const activeForbidden = [
  { name: 'obsolete presence authorization vocabulary', pattern: /owner[-_ ]?presence|OwnerPresence/ },
  { name: 'caller-owned transaction or fixture field', pattern: /\b(?:intentDigest|intentNonce|wallet_mpc_signing|spokenPhrase|fixtureBehavior)\b/ },
  { name: 'obsolete liveness bypass', pattern: /\bliveness_not_required\b/ },
  { name: 'obsolete VoiceID Router adapter', pattern: /sdkRouterApiExtension|createVoiceIdRouterApi/ },
  { name: 'obsolete route family', pattern: /\/voice-id\/(?:enrollment|verification|owner-presence)(?:\/|['"`])/ },
  { name: 'wallet or Router signing integration', pattern: /\b(?:SigningWorker|WalletSigningAuthorization|RouterApiModule)\b/ },
  { name: 'signing-eligible evidence metadata', pattern: /signingEligible\s*:\s*true/ },
  { name: 'wildcard biometric API CORS', pattern: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/ },
  { name: 'unparsed generic VoiceID client response', pattern: /VoiceIdClientResponse|kind:\s*['"]ok['"];\s*value:\s*unknown/ },
];

async function collectFiles(path, files) {
  const entries = await readdir(path, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = join(path, entry.name);

    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        await collectFiles(entryPath, files);
      }
      continue;
    }

    if (entry.isFile() && scannedExtensions.has(extname(entry.name))) {
      files.push(entryPath);
    }
  }
}

const files = [];
const activeFiles = [];

for (const scannedRoot of scannedRoots) {
  const path = join(voiceIdRoot, scannedRoot);

  if (extname(path) === '.md') {
    files.push(path);
    continue;
  }

  await collectFiles(path, files);
}

for (const activeRoot of activeRoots) {
  await collectFiles(join(voiceIdRoot, activeRoot), activeFiles);
}

const failures = [];

for (const file of files) {
  const content = await readFile(file, 'utf8');

  for (const rule of forbidden) {
    if (rule.pattern.test(content)) {
      failures.push(`${relative(voiceIdRoot, file)}: ${rule.name}`);
    }
  }
}

for (const file of activeFiles) {
  const content = await readFile(file, 'utf8');

  for (const rule of activeForbidden) {
    if (rule.pattern.test(content)) {
      failures.push(`${relative(voiceIdRoot, file)}: ${rule.name}`);
    }
  }
}

if (failures.length > 0) {
  console.error('VoiceID signing architecture check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('VoiceID signing architecture check passed.');
