import { readFile } from 'node:fs/promises';

const checks = [
  {
    filePath: 'deploy/cloudflare/verifier-container/Dockerfile',
    required: [
      { name: 'Python 3.11 slim base image', pattern: /FROM python:3\.11-slim/ },
      { name: 'ffmpeg runtime dependency', pattern: /\bffmpeg\b/ },
      { name: 'libsndfile runtime dependency', pattern: /\blibsndfile1\b/ },
      { name: 'CPU PyTorch install', pattern: /download\.pytorch\.org\/whl\/cpu/ },
      { name: 'pinned Torch version', pattern: /torch==2\.6\.\*/ },
      { name: 'pinned Torchaudio version', pattern: /torchaudio==2\.6\.\*/ },
      { name: 'ECAPA backend default', pattern: /VOICEID_VERIFIER_BACKEND=ecapa/ },
      { name: 'Cloudflare bind host', pattern: /VOICEID_VERIFIER_HOST=0\.0\.0\.0/ },
      { name: 'verifier port', pattern: /VOICEID_VERIFIER_PORT=8797/ },
      { name: 'ECAPA model cache env', pattern: /VOICEID_ECAPA_MODEL_CACHE/ },
      { name: 'optional model preload', pattern: /PRELOAD_ECAPA_MODEL/ },
      { name: 'HTTP health check', pattern: /\/health/ },
      { name: 'HTTP port expose', pattern: /EXPOSE 8797/ },
      { name: 'verifier HTTP command', pattern: /voiceid_verifier\.app", "serve_http/ },
    ],
  },
  {
    filePath: '.dockerignore',
    required: [
      { name: 'fixture exclusion', pattern: /^fixtures$/m },
      { name: 'research exclusion', pattern: /^research$/m },
      { name: 'spike exclusion', pattern: /^verifier-spike$/m },
      { name: 'model cache exclusion', pattern: /^verifier\/\.cache$/m },
      { name: 'webm audio exclusion', pattern: /^\*\.webm$/m },
      { name: 'mp3 audio exclusion', pattern: /^\*\.mp3$/m },
      { name: 'wav audio exclusion', pattern: /^\*\.wav$/m },
      { name: 'ogg audio exclusion', pattern: /^\*\.ogg$/m },
    ],
  },
  {
    filePath: 'verifier/pyproject.toml',
    required: [
      { name: 'setuptools build backend', pattern: /build-backend = "setuptools\.build_meta"/ },
      { name: 'package finder config', pattern: /\[tool\.setuptools\.packages\.find\]/ },
      { name: 'SpeechBrain ECAPA dependency', pattern: /"speechbrain>=1\.0\.0"/ },
      { name: 'pinned Torch dependency', pattern: /"torch==2\.6\.\*"/ },
      { name: 'pinned Torchaudio dependency', pattern: /"torchaudio==2\.6\.\*"/ },
    ],
  },
  {
    filePath: 'deploy/cloudflare/verifier-container/README.md',
    required: [
      { name: 'Cloudflare Worker shape', pattern: /Cloudflare Worker/ },
      { name: 'python-http transport reference', pattern: /python-http/ },
      { name: 'container verifier URL env', pattern: /VOICEID_PYTHON_VERIFIER_URL/ },
      { name: 'preload build arg docs', pattern: /PRELOAD_ECAPA_MODEL=1/ },
    ],
  },
];

const failures = [];

for (const check of checks) {
  const content = await readFile(check.filePath, 'utf8');
  for (const required of check.required) {
    if (!required.pattern.test(content)) {
      failures.push(`${check.filePath}: missing ${required.name}`);
    }
  }
}

if (failures.length > 0) {
  console.error('Container packaging check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Container packaging check passed.');
