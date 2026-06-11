import {
  VoiceIdClient,
  VoiceIdRecorder,
  buildManifestFromCapturedVoiceIdFixtures,
  createCapturedVoiceIdFixture,
  downloadVoiceIdFixtureAudio,
  downloadVoiceIdFixtureManifest,
  type CapturedVoiceIdFixture,
} from '../../client/src/index.ts';
import {
  VOICE_ID_FIXTURE_EXPECTED_RELATIONS,
  type VoiceIdFixtureExpectedRelation,
} from '../../shared/src/index.ts';

type DemoState =
  | { kind: 'idle'; message: string }
  | { kind: 'enrolling'; enrollmentId: string; acceptedSampleCount: number; message: string }
  | { kind: 'enrolled'; enrollmentId: string; message: string }
  | { kind: 'verifying'; enrollmentId: string; verificationId: string; message: string }
  | { kind: 'accepted'; enrollmentId: string; message: string }
  | { kind: 'rejected'; enrollmentId: string; reason: string; message: string }
  | { kind: 'uncertain'; enrollmentId: string; reason: string; message: string }
  | { kind: 'error'; message: string };

type ApiEnvelope =
  | {
      kind: 'ok';
      value: unknown;
    }
  | {
      kind: 'error';
      error: { kind: string; message: string };
    };

type DemoDiagnostics = {
  quality: string;
  phrase: string;
  speaker: string;
  finalResult: string;
};

type FixtureCaptureForm = {
  speakerLabel: string;
  phraseLabel: string;
  expectedRelation: VoiceIdFixtureExpectedRelation;
  captureDevice: string;
  durationMs: number;
  environmentNotes: string;
};

type VerificationApiResult =
  | {
      kind: 'accepted';
      checks: VerificationChecks;
    }
  | {
      kind: 'rejected';
      reason: string;
      checks: VerificationChecks;
    }
  | {
      kind: 'uncertain';
      reason: string;
      checks: VerificationChecks;
    };

type VerificationChecks = {
  quality: {
    kind: string;
    reason?: string;
    durationMs: number;
    signalScore?: number;
  };
  phrase: {
    kind: string;
    reason?: string;
    expectedNormalized: string;
    spokenNormalized: string;
    confidence: number;
  };
  speaker: {
    kind: string;
    reason?: string;
    score: number;
    threshold: number;
  };
};

const userId = 'demo-owner';
const phrase = 'Walking on clouds';
const client = new VoiceIdClient({
  baseUrl: 'http://127.0.0.1:8787',
  fetch,
});
const recorder = new VoiceIdRecorder();
let state: DemoState = { kind: 'idle', message: 'Ready' };
let diagnostics: DemoDiagnostics = {
  quality: 'none',
  phrase: 'none',
  speaker: 'none',
  finalResult: 'none',
};
let fixtureForm: FixtureCaptureForm = {
  speakerLabel: 'owner',
  phraseLabel: phrase,
  expectedRelation: 'owner_enrollment',
  captureDevice: 'browser microphone',
  durationMs: 3500,
  environmentNotes: 'quiet room',
};
let fixtureCaptureMessage = 'No fixtures captured';
let capturedFixtures: CapturedVoiceIdFixture[] = [];
let enrollmentAttempts = 0;
let verificationAttempts = 0;

const app = document.querySelector<HTMLElement>('#app');
if (!app) {
  throw new Error('missing app root');
}
const appRoot = app;

render();

function render(): void {
  const controls = getDemoControls(state);
  appRoot.innerHTML = `
    <section class="shell">
      <header>
        <h1>VoiceID MVP</h1>
        <p>Speaker verification demo. Phase 1 does not perform liveness checks.</p>
      </header>
      <section class="panel">
        <dl>
          <div><dt>Status</dt><dd>${escapeHtml(state.kind)}</dd></div>
          <div><dt>Prompt</dt><dd>${escapeHtml(phrase)}</dd></div>
          <div><dt>Message</dt><dd>${escapeHtml(state.message)}</dd></div>
          <div><dt>Quality</dt><dd>${escapeHtml(diagnostics.quality)}</dd></div>
          <div><dt>Phrase</dt><dd>${escapeHtml(diagnostics.phrase)}</dd></div>
          <div><dt>Speaker</dt><dd>${escapeHtml(diagnostics.speaker)}</dd></div>
          <div><dt>Final</dt><dd>${escapeHtml(diagnostics.finalResult)}</dd></div>
        </dl>
        <div class="actions">
          <button id="start-enrollment">Start Enrollment</button>
          <button id="record-enrollment" ${disabledAttribute(!controls.canRecordEnrollment)}>Record Enrollment Sample</button>
          <button id="finalize-enrollment" ${disabledAttribute(!controls.canFinalizeEnrollment)}>Finalize Enrollment</button>
          <button id="start-verification" ${disabledAttribute(!controls.canStartVerification)}>Start Verification</button>
          <button id="record-verification" ${disabledAttribute(!controls.canRecordVerification)}>Record Verification</button>
        </div>
      </section>
      ${renderFixtureCapturePanel()}
    </section>
  `;

  document.querySelector('#start-enrollment')?.addEventListener('click', startEnrollment);
  document.querySelector('#record-enrollment')?.addEventListener('click', recordEnrollmentSample);
  document.querySelector('#finalize-enrollment')?.addEventListener('click', finalizeEnrollment);
  document.querySelector('#start-verification')?.addEventListener('click', startVerification);
  document.querySelector('#record-verification')?.addEventListener('click', recordVerificationSample);
  bindFixtureCaptureControls();
}

function renderFixtureCapturePanel(): string {
  const hasFixtures = capturedFixtures.length > 0;
  return `
    <section class="panel fixture-panel">
      <h2>Fixture Capture</h2>
      <div class="fixture-grid">
        <label>
          <span>Speaker</span>
          <input id="fixture-speaker-label" value="${escapeHtml(fixtureForm.speakerLabel)}" />
        </label>
        <label>
          <span>Phrase</span>
          <input id="fixture-phrase-label" value="${escapeHtml(fixtureForm.phraseLabel)}" />
        </label>
        <label>
          <span>Relation</span>
          <select id="fixture-relation">
            ${VOICE_ID_FIXTURE_EXPECTED_RELATIONS.map(
              (relation) =>
                `<option value="${relation}" ${
                  fixtureForm.expectedRelation === relation ? 'selected' : ''
                }>${escapeHtml(formatFixtureRelation(relation))}</option>`,
            ).join('')}
          </select>
        </label>
        <label>
          <span>Device</span>
          <input id="fixture-capture-device" value="${escapeHtml(fixtureForm.captureDevice)}" />
        </label>
        <label>
          <span>Duration ms</span>
          <input id="fixture-duration-ms" type="number" min="400" max="10000" step="100" value="${fixtureForm.durationMs}" />
        </label>
        <label class="wide">
          <span>Notes</span>
          <textarea id="fixture-environment-notes" rows="2">${escapeHtml(fixtureForm.environmentNotes)}</textarea>
        </label>
      </div>
      <p class="notice">Local fixtures include raw voice audio. Keep exports local and delete clips after model evaluation.</p>
      <div class="actions">
        <button id="capture-fixture">Capture Fixture</button>
        <button id="download-fixture-manifest" ${disabledAttribute(!hasFixtures)}>Download Manifest</button>
        <button id="download-fixture-audio-all" ${disabledAttribute(!hasFixtures)}>Download All Audio</button>
      </div>
      <div class="fixture-status">${escapeHtml(fixtureCaptureMessage)}</div>
      <ul class="fixture-list">
        ${capturedFixtures.map(renderCapturedFixtureRow).join('')}
      </ul>
    </section>
  `;
}

function renderCapturedFixtureRow(fixture: CapturedVoiceIdFixture, index: number): string {
  return `
    <li>
      <div>
        <strong>${escapeHtml(fixture.entry.audioFileName)}</strong>
        <span>${escapeHtml(fixture.entry.expectedRelation)}; ${escapeHtml(fixture.entry.speakerLabel)}; ${fixture.entry.durationMs}ms</span>
      </div>
      <button data-download-fixture="${index}">Download Audio</button>
    </li>
  `;
}

function bindFixtureCaptureControls(): void {
  bindTextInput('fixture-speaker-label', (value) => {
    fixtureForm = { ...fixtureForm, speakerLabel: normalizeFixtureText(value, 'owner') };
  });
  bindTextInput('fixture-phrase-label', (value) => {
    fixtureForm = { ...fixtureForm, phraseLabel: normalizeFixtureText(value, phrase) };
  });
  bindTextInput('fixture-capture-device', (value) => {
    fixtureForm = {
      ...fixtureForm,
      captureDevice: normalizeFixtureText(value, 'browser microphone'),
    };
  });
  bindTextInput('fixture-environment-notes', (value) => {
    fixtureForm = { ...fixtureForm, environmentNotes: normalizeFixtureText(value, 'unspecified') };
  });

  const relation = document.querySelector<HTMLSelectElement>('#fixture-relation');
  relation?.addEventListener('change', () => {
    fixtureForm = {
      ...fixtureForm,
      expectedRelation: parseFixtureRelationSelection(relation.value),
    };
  });

  const duration = document.querySelector<HTMLInputElement>('#fixture-duration-ms');
  duration?.addEventListener('input', () => {
    fixtureForm = {
      ...fixtureForm,
      durationMs: normalizeFixtureDurationMs(duration.value),
    };
  });

  document.querySelector('#capture-fixture')?.addEventListener('click', captureFixture);
  document.querySelector('#download-fixture-manifest')?.addEventListener('click', downloadManifest);
  document.querySelector('#download-fixture-audio-all')?.addEventListener('click', downloadAllAudio);
  document.querySelectorAll<HTMLButtonElement>('[data-download-fixture]').forEach((button) => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.downloadFixture);
      const fixture = capturedFixtures[index];
      if (fixture) downloadVoiceIdFixtureAudio(fixture);
    });
  });
}

function bindTextInput(elementId: string, update: (value: string) => void): void {
  const input = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(`#${elementId}`);
  input?.addEventListener('input', () => update(input.value));
}

async function startEnrollment(): Promise<void> {
  const response = parseEnvelope(await client.startEnrollment({ userId, phrase }));
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as { record: { enrollmentId: string; acceptedSampleCount: number } };
  enrollmentAttempts = 0;
  resetDiagnostics();
  state = {
    kind: 'enrolling',
    enrollmentId: value.record.enrollmentId,
    acceptedSampleCount: value.record.acceptedSampleCount,
    message: 'Enrollment issued',
  };
  render();
}

async function recordEnrollmentSample(): Promise<void> {
  if (state.kind !== 'enrolling') {
    setError('Start enrollment first');
    return;
  }

  const recorded = await recorder.recordClip({
    durationMs: 1800,
    timeoutMs: 3000,
    fixtureSpeakerLabel: 'owner',
  });
  if (recorded.kind !== 'recorded') {
    setError(recorded.kind === 'error' ? recorded.reason : 'recording did not finish');
    return;
  }

  enrollmentAttempts += 1;
  const response = parseEnvelope(
    await client.uploadEnrollmentSample({
      blob: recorded.blob,
      metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
      userId,
      enrollmentId: state.enrollmentId,
      expectedPhrase: phrase,
      spokenPhrase: phrase,
      attemptNumber: enrollmentAttempts,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as {
    acceptedSampleCount: number;
    quality: VerificationChecks['quality'];
  };
  diagnostics = {
    ...diagnostics,
    quality: formatQuality(value.quality),
    finalResult: `enrollment samples accepted: ${value.acceptedSampleCount}`,
  };
  state = {
    ...state,
    acceptedSampleCount: value.acceptedSampleCount,
    message: `Accepted samples: ${value.acceptedSampleCount}`,
  };
  render();
}

async function finalizeEnrollment(): Promise<void> {
  if (state.kind !== 'enrolling') {
    setError('Record enrollment samples first');
    return;
  }

  const response = parseEnvelope(
    await client.finalizeEnrollment({
      userId,
      enrollmentId: state.enrollmentId,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  state = {
    kind: 'enrolled',
    enrollmentId: state.enrollmentId,
    message: 'Enrollment finalized',
  };
  render();
}

async function startVerification(): Promise<void> {
  const enrollmentId = getVerificationEnrollmentId(state);
  if (enrollmentId === null) {
    setError('Finalize enrollment first');
    return;
  }

  const response = parseEnvelope(
    await client.startVerification({
      userId,
      enrollmentId,
      phrase,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as { record: { verificationId: string } };
  verificationAttempts = 0;
  diagnostics = {
    ...diagnostics,
    finalResult: 'verification issued',
  };
  state = {
    kind: 'verifying',
    enrollmentId,
    verificationId: value.record.verificationId,
    message: 'Verification issued',
  };
  render();
}

async function recordVerificationSample(): Promise<void> {
  if (state.kind !== 'verifying') {
    setError('Start verification first');
    return;
  }

  const recorded = await recorder.recordClip({
    durationMs: 1800,
    timeoutMs: 3000,
    fixtureSpeakerLabel: 'owner',
  });
  if (recorded.kind !== 'recorded') {
    setError(recorded.kind === 'error' ? recorded.reason : 'recording did not finish');
    return;
  }

  verificationAttempts += 1;
  const response = parseEnvelope(
    await client.uploadVerificationSample({
      blob: recorded.blob,
      metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
      userId,
      enrollmentId: state.enrollmentId,
      verificationId: state.verificationId,
      expectedPhrase: phrase,
      spokenPhrase: phrase,
      attemptNumber: verificationAttempts,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as VerificationApiResult;
  const enrollmentId = state.enrollmentId;
  diagnostics = {
    quality: formatQuality(value.checks.quality),
    phrase: formatPhrase(value.checks.phrase),
    speaker: formatSpeaker(value.checks.speaker),
    finalResult: value.kind,
  };
  if (value.kind === 'accepted') {
    state = { kind: 'accepted', enrollmentId, message: 'VoiceID accepted' };
  } else if (value.kind === 'rejected') {
    state = { kind: 'rejected', enrollmentId, reason: value.reason ?? 'rejected', message: 'VoiceID rejected' };
  } else {
    state = { kind: 'uncertain', enrollmentId, reason: value.reason ?? 'uncertain', message: 'VoiceID uncertain' };
  }
  render();
}

async function captureFixture(): Promise<void> {
  readFixtureFormFromDom();
  fixtureCaptureMessage = 'Recording fixture';
  render();

  const recorded = await recorder.recordClip({
    durationMs: fixtureForm.durationMs,
    timeoutMs: fixtureForm.durationMs + 1500,
    fixtureSpeakerLabel: fixtureForm.speakerLabel,
  });
  if (recorded.kind !== 'recorded') {
    fixtureCaptureMessage =
      recorded.kind === 'error'
        ? `Fixture recording failed: ${formatRecorderError(recorded.reason)}`
        : 'Fixture recording did not finish';
    render();
    return;
  }

  const metadata = recorder.buildMetadata({ fixtureSpeakerLabel: fixtureForm.speakerLabel });
  const fixture = createCapturedVoiceIdFixture({
    blob: recorded.blob,
    metadata,
    speakerLabel: fixtureForm.speakerLabel,
    phraseLabel: fixtureForm.phraseLabel,
    expectedRelation: fixtureForm.expectedRelation,
    captureDevice: fixtureForm.captureDevice,
    environmentNotes: fixtureForm.environmentNotes,
  });
  capturedFixtures = [...capturedFixtures, fixture];
  fixtureCaptureMessage = `Captured ${capturedFixtures.length} fixture${capturedFixtures.length === 1 ? '' : 's'}`;
  render();
}

function downloadManifest(): void {
  if (capturedFixtures.length === 0) return;
  const manifest = buildManifestFromCapturedVoiceIdFixtures({ fixtures: capturedFixtures });
  downloadVoiceIdFixtureManifest(manifest);
  fixtureCaptureMessage = `Manifest exported with ${manifest.entries.length} fixture${manifest.entries.length === 1 ? '' : 's'}`;
  render();
}

function downloadAllAudio(): void {
  if (capturedFixtures.length === 0) return;
  for (const fixture of capturedFixtures) {
    downloadVoiceIdFixtureAudio(fixture);
  }
  fixtureCaptureMessage = `Queued ${capturedFixtures.length} audio download${capturedFixtures.length === 1 ? '' : 's'}`;
  render();
}

function readFixtureFormFromDom(): void {
  const speakerLabel =
    document.querySelector<HTMLInputElement>('#fixture-speaker-label')?.value ?? fixtureForm.speakerLabel;
  const phraseLabel =
    document.querySelector<HTMLInputElement>('#fixture-phrase-label')?.value ?? fixtureForm.phraseLabel;
  const captureDevice =
    document.querySelector<HTMLInputElement>('#fixture-capture-device')?.value ??
    fixtureForm.captureDevice;
  const environmentNotes =
    document.querySelector<HTMLTextAreaElement>('#fixture-environment-notes')?.value ??
    fixtureForm.environmentNotes;
  const durationMs =
    document.querySelector<HTMLInputElement>('#fixture-duration-ms')?.value ??
    String(fixtureForm.durationMs);
  const expectedRelation =
    document.querySelector<HTMLSelectElement>('#fixture-relation')?.value ??
    fixtureForm.expectedRelation;

  fixtureForm = {
    speakerLabel: normalizeFixtureText(speakerLabel, 'owner'),
    phraseLabel: normalizeFixtureText(phraseLabel, phrase),
    expectedRelation: parseFixtureRelationSelection(expectedRelation),
    captureDevice: normalizeFixtureText(captureDevice, 'browser microphone'),
    durationMs: normalizeFixtureDurationMs(durationMs),
    environmentNotes: normalizeFixtureText(environmentNotes, 'unspecified'),
  };
}

function parseEnvelope(value: unknown): ApiEnvelope {
  return value as ApiEnvelope;
}

function setError(message: string): void {
  state = { kind: 'error', message };
  render();
}

function resetDiagnostics(): void {
  diagnostics = {
    quality: 'none',
    phrase: 'none',
    speaker: 'none',
    finalResult: 'none',
  };
}

function getDemoControls(currentState: DemoState): {
  canRecordEnrollment: boolean;
  canFinalizeEnrollment: boolean;
  canStartVerification: boolean;
  canRecordVerification: boolean;
} {
  return {
    canRecordEnrollment: currentState.kind === 'enrolling',
    canFinalizeEnrollment:
      currentState.kind === 'enrolling' && currentState.acceptedSampleCount >= 3,
    canStartVerification: getVerificationEnrollmentId(currentState) !== null,
    canRecordVerification: currentState.kind === 'verifying',
  };
}

function getVerificationEnrollmentId(currentState: DemoState): string | null {
  switch (currentState.kind) {
    case 'enrolled':
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      return currentState.enrollmentId;
    case 'idle':
    case 'enrolling':
    case 'verifying':
    case 'error':
      return null;
  }
}

function disabledAttribute(disabled: boolean): string {
  return disabled ? 'disabled aria-disabled="true"' : '';
}

function formatQuality(quality: VerificationChecks['quality']): string {
  if (quality.kind === 'accepted') {
    return `${quality.kind}; ${quality.durationMs}ms; signal ${formatNumber(quality.signalScore ?? 0)}`;
  }

  return `${quality.kind}; ${quality.reason ?? 'no reason'}; ${quality.durationMs}ms`;
}

function formatPhrase(phraseResult: VerificationChecks['phrase']): string {
  return `${phraseResult.kind}; ${phraseResult.spokenNormalized}; confidence ${formatNumber(phraseResult.confidence)}`;
}

function formatSpeaker(speaker: VerificationChecks['speaker']): string {
  return `${speaker.kind}; score ${formatNumber(speaker.score)} / threshold ${formatNumber(speaker.threshold)}`;
}

function formatRecorderError(reason: string): string {
  if (reason === 'empty_recording') {
    return 'no audio frames captured; use 3500ms or longer and start speaking after the phone mic is active';
  }
  return reason;
}

function formatNumber(value: number): string {
  return value.toFixed(2);
}

function formatFixtureRelation(relation: VoiceIdFixtureExpectedRelation): string {
  switch (relation) {
    case 'owner_enrollment':
      return 'Owner enrollment';
    case 'owner_verification':
      return 'Owner verification';
    case 'different_speaker':
      return 'Different speaker';
    case 'wrong_phrase':
      return 'Wrong phrase';
    case 'noisy':
      return 'Noisy';
    case 'too_short':
      return 'Too short';
  }
}

function parseFixtureRelationSelection(value: string): VoiceIdFixtureExpectedRelation {
  if (
    VOICE_ID_FIXTURE_EXPECTED_RELATIONS.includes(value as VoiceIdFixtureExpectedRelation)
  ) {
    return value as VoiceIdFixtureExpectedRelation;
  }
  return 'owner_enrollment';
}

function normalizeFixtureText(value: string, fallback: string): string {
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : fallback;
}

function normalizeFixtureDurationMs(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fixtureForm.durationMs;
  return Math.min(10_000, Math.max(400, Math.round(parsed)));
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const style = document.createElement('style');
style.textContent = `
  body {
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #f6f7f8;
    color: #172026;
  }

  .shell {
    max-width: 760px;
    margin: 0 auto;
    padding: 40px 20px;
  }

  h1 {
    margin: 0 0 8px;
    font-size: 32px;
  }

  p {
    margin: 0 0 24px;
    color: #4b5a64;
  }

  .panel {
    border: 1px solid #d9e0e5;
    border-radius: 8px;
    background: #fff;
    padding: 20px;
  }

  .fixture-panel {
    margin-top: 16px;
  }

  h2 {
    margin: 0 0 16px;
    font-size: 18px;
  }

  dl {
    margin: 0 0 20px;
    display: grid;
    gap: 10px;
  }

  dl div {
    display: grid;
    grid-template-columns: 120px minmax(0, 1fr);
    gap: 12px;
  }

  dt {
    color: #5d6b75;
    font-size: 13px;
  }

  dd {
    margin: 0;
    font-weight: 600;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .fixture-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 14px;
  }

  label {
    display: grid;
    gap: 5px;
    color: #5d6b75;
    font-size: 13px;
  }

  label.wide {
    grid-column: 1 / -1;
  }

  input,
  select,
  textarea {
    width: 100%;
    box-sizing: border-box;
    border: 1px solid #c8d1d8;
    border-radius: 6px;
    background: #fff;
    color: #172026;
    min-height: 36px;
    padding: 7px 9px;
    font: inherit;
  }

  textarea {
    resize: vertical;
  }

  .notice,
  .fixture-status {
    margin: 0 0 14px;
    color: #5d6b75;
    font-size: 13px;
  }

  .fixture-status {
    margin-top: 12px;
  }

  .fixture-list {
    list-style: none;
    padding: 0;
    margin: 12px 0 0;
    display: grid;
    gap: 8px;
  }

  .fixture-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    border-top: 1px solid #edf1f4;
    padding-top: 8px;
  }

  .fixture-list strong,
  .fixture-list span {
    display: block;
    overflow-wrap: anywhere;
  }

  .fixture-list span {
    color: #5d6b75;
    font-size: 13px;
  }

  button {
    border: 1px solid #b7c2ca;
    border-radius: 6px;
    background: #172026;
    color: #fff;
    min-height: 38px;
    padding: 0 12px;
    font: inherit;
    cursor: pointer;
  }

  button:disabled {
    background: #d6dde2;
    border-color: #c4cdd4;
    color: #687783;
    cursor: not-allowed;
  }

  @media (max-width: 640px) {
    .fixture-grid {
      grid-template-columns: 1fr;
    }

    .fixture-list li {
      align-items: stretch;
      flex-direction: column;
    }
  }
`;
document.head.append(style);
