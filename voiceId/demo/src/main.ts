import './styles.css';
import { VoiceIdClient, VoiceIdRecorder } from '../../client/src/index.ts';
import { assertNever, type VoiceIdApiResponse } from '../../shared/src/index.ts';

type DemoState =
  | { kind: 'idle'; message: string }
  | { kind: 'requesting_enrollment'; message: string }
  | {
      kind: 'enrollment_ready';
      enrollmentId: string;
      prompts: readonly string[];
      captureDurationMs: number;
      message: string;
    }
  | {
      kind: 'enrollment_recording';
      enrollmentId: string;
      prompts: readonly string[];
      captureDurationMs: number;
      message: string;
    }
  | {
      kind: 'enrollment_microphone_request';
      enrollmentId: string;
      prompts: readonly string[];
      captureDurationMs: number;
      message: string;
    }
  | { kind: 'submitting_enrollment'; enrollmentId: string; message: string }
  | { kind: 'enrolled'; enrollmentId: string; message: string }
  | { kind: 'requesting_verification'; enrollmentId: string; message: string }
  | {
      kind: 'verification_ready';
      enrollmentId: string;
      verificationId: string;
      prompt: string;
      message: string;
    }
  | {
      kind: 'verification_recording';
      enrollmentId: string;
      verificationId: string;
      prompt: string;
      captureDurationMs: number;
      message: string;
    }
  | {
      kind: 'verification_microphone_request';
      enrollmentId: string;
      verificationId: string;
      prompt: string;
      captureDurationMs: number;
      message: string;
    }
  | {
      kind: 'submitting_verification';
      enrollmentId: string;
      verificationId: string;
      message: string;
    }
  | {
      kind: 'evidence';
      enrollmentId: string;
      resultKind: string;
      evidenceKind: string;
      message: string;
    }
  | { kind: 'error'; message: string };

type RecordingCountdown = {
  durationMs: number;
  endsAtMs: number;
};

const userId = 'voiceid-e0-demo-user';
const client = new VoiceIdClient({ baseUrl: 'http://127.0.0.1:5052', fetch });
const recorder = new VoiceIdRecorder();
const app = requireAppElement();
let recordingCountdown: RecordingCountdown | null = null;
let recordingCountdownTimerId: number | null = null;
let state: DemoState = {
  kind: 'idle',
  message: 'Start an experimental browser enrollment. This demo never authorizes signing.',
};

render();

function render(): void {
  app.innerHTML = `
    <section class="voiceid-shell">
      <div class="voiceid-card">
        <p class="eyebrow">E0 RESEARCH ONLY</p>
        <h1>VoiceID evidence lab</h1>
        <p class="lede">Browser capture produces signing-ineligible evidence. Enrollment uses one continuous guided recording.</p>
        ${renderStateBody(state)}
        <p class="status" data-kind="${escapeHtml(state.kind)}">${escapeHtml(state.message)}</p>
      </div>
    </section>
  `;
  bindActions();
}

function renderStateBody(current: DemoState): string {
  switch (current.kind) {
    case 'idle':
      return '<button id="start-enrollment" type="button">Start enrollment</button>';
    case 'enrollment_ready':
      return `
        <h2>One continuous enrollment recording</h2>
        <p class="instruction">Press record, then read every phrase aloud from top to bottom. The phrases remain visible while the microphone is active.</p>
        ${renderPromptSequence(current.prompts, 'prompt-list')}
        <button id="record-enrollment" type="button">Start ${formatDurationSeconds(current.captureDurationMs)}-second recording</button>
      `;
    case 'enrollment_recording':
      return renderEnrollmentRecording(current);
    case 'enrollment_microphone_request':
      return renderEnrollmentMicrophoneRequest(current);
    case 'requesting_enrollment':
    case 'submitting_enrollment':
    case 'requesting_verification':
    case 'submitting_verification':
      return renderPendingState();
    case 'enrolled':
      return '<button id="start-verification" type="button">Issue verification challenge</button>';
    case 'verification_ready':
      return `
        <h2>Fresh phrase</h2>
        <blockquote>${escapeHtml(current.prompt)}</blockquote>
        <button id="record-verification" type="button">Record response</button>
      `;
    case 'verification_recording':
      return renderVerificationRecording(current);
    case 'verification_microphone_request':
      return renderVerificationMicrophoneRequest(current);
    case 'evidence':
      return `
        <dl>
          <div><dt>Result</dt><dd>${escapeHtml(current.resultKind)}</dd></div>
          <div><dt>Evidence tier</dt><dd>${escapeHtml(current.evidenceKind)}</dd></div>
          <div><dt>Signing eligible</dt><dd>No</dd></div>
        </dl>
        <button id="start-verification" type="button">Try another challenge</button>
      `;
    case 'error':
      return '<button id="reset-demo" type="button">Reset</button>';
    default:
      return assertNever(current);
  }
}

function bindActions(): void {
  document.querySelector('#start-enrollment')?.addEventListener('click', startEnrollment);
  document.querySelector('#record-enrollment')?.addEventListener('click', recordEnrollment);
  document.querySelector('#start-verification')?.addEventListener('click', startVerification);
  document.querySelector('#record-verification')?.addEventListener('click', recordVerification);
  document.querySelector('#reset-demo')?.addEventListener('click', resetDemo);
}

async function startEnrollment(): Promise<void> {
  state = {
    kind: 'requesting_enrollment',
    message: 'Requesting a server-owned enrollment prompt sequence',
  };
  render();
  try {
    const response = await client.startEnrollment({ userId });
    const value = unwrapVoiceIdApiResponse(response);
    state = {
      kind: 'enrollment_ready',
      enrollmentId: value.enrollmentId,
      prompts: value.promptSequence,
      captureDurationMs: enrollmentCaptureDurationMs(value.minimumCaptureMs),
      message: 'Review the phrases, then start one continuous recording.',
    };
  } catch (error) {
    state = errorState(error);
  }
  render();
}

async function recordEnrollment(): Promise<void> {
  if (state.kind !== 'enrollment_ready') return;
  const context = state;
  state = {
    kind: 'enrollment_microphone_request',
    enrollmentId: context.enrollmentId,
    prompts: context.prompts,
    captureDurationMs: context.captureDurationMs,
    message: 'Allow microphone access to begin the recording.',
  };
  render();
  try {
    const recording = await recorder.recordClip({
      durationMs: context.captureDurationMs,
      timeoutMs: 32_000,
      onRecordingStart: beginEnrollmentRecording,
    });
    stopRecordingCountdown();
    if (recording.kind !== 'recorded') throw new Error(recordingFailureReason(recording));
    state = {
      kind: 'submitting_enrollment',
      enrollmentId: context.enrollmentId,
      message: 'Recording complete. Evaluating enrollment evidence.',
    };
    render();
    const response = await client.submitEnrollmentRecording({
      blob: recording.blob,
      metadata: recorder.buildMetadata(),
      userId,
      enrollmentId: context.enrollmentId,
    });
    const value = unwrapVoiceIdApiResponse(response);
    state =
      value.kind === 'enrolled'
        ? {
            kind: 'enrolled',
            enrollmentId: value.enrollmentId,
            message: 'Enrollment committed atomically.',
          }
        : { kind: 'error', message: `Enrollment rejected: ${value.reason}` };
  } catch (error) {
    stopRecordingCountdown();
    state = errorState(error);
  }
  render();
}

async function startVerification(): Promise<void> {
  const enrollmentId = activeEnrollmentId(state);
  if (enrollmentId === null) return;
  state = {
    kind: 'requesting_verification',
    enrollmentId,
    message: 'Issuing a fresh server-owned challenge',
  };
  render();
  try {
    const response = await client.startVerification({ userId, enrollmentId });
    const value = unwrapVoiceIdApiResponse(response);
    state = {
      kind: 'verification_ready',
      enrollmentId: value.enrollmentId,
      verificationId: value.verificationId,
      prompt: value.prompt,
      message: 'This challenge accepts exactly one capture.',
    };
  } catch (error) {
    state = errorState(error);
  }
  render();
}

async function recordVerification(): Promise<void> {
  if (state.kind !== 'verification_ready') return;
  const context = state;
  const captureDurationMs = 4_000;
  state = {
    kind: 'verification_microphone_request',
    enrollmentId: context.enrollmentId,
    verificationId: context.verificationId,
    prompt: context.prompt,
    captureDurationMs,
    message: 'Allow microphone access to begin the recording.',
  };
  render();
  try {
    const recording = await recorder.recordClip({
      durationMs: captureDurationMs,
      timeoutMs: 8_000,
      onRecordingStart: beginVerificationRecording,
    });
    stopRecordingCountdown();
    if (recording.kind !== 'recorded') throw new Error(recordingFailureReason(recording));
    state = {
      kind: 'submitting_verification',
      enrollmentId: context.enrollmentId,
      verificationId: context.verificationId,
      message: 'Recording complete. Evaluating verification evidence.',
    };
    render();
    const response = await client.submitVerificationRecording({
      blob: recording.blob,
      metadata: recorder.buildMetadata(),
      userId,
      enrollmentId: context.enrollmentId,
      verificationId: context.verificationId,
    });
    const value = unwrapVoiceIdApiResponse(response);
    state = {
      kind: 'evidence',
      enrollmentId: context.enrollmentId,
      resultKind: value.kind,
      evidenceKind: value.kind === 'evidence_observed' ? value.evidence.kind : 'none',
      message: 'Verification completed. The result cannot enter wallet signing.',
    };
  } catch (error) {
    stopRecordingCountdown();
    state = errorState(error);
  }
  render();
}

function resetDemo(): void {
  stopRecordingCountdown();
  recorder.clearRecording();
  state = { kind: 'idle', message: 'Demo reset.' };
  render();
}

function recordingFailureReason(
  recording: Exclude<Awaited<ReturnType<VoiceIdRecorder['recordClip']>>, { kind: 'recorded' }>,
): string {
  return recording.kind === 'error' ? recording.reason : 'recording did not complete';
}

function unwrapVoiceIdApiResponse<TValue>(response: VoiceIdApiResponse<TValue>): TValue {
  if (response.kind === 'error') throw new Error(response.error.message);
  return response.value;
}

function activeEnrollmentId(current: DemoState): string | null {
  switch (current.kind) {
    case 'enrolled':
    case 'evidence':
      return current.enrollmentId;
    case 'idle':
    case 'requesting_enrollment':
    case 'enrollment_ready':
    case 'enrollment_microphone_request':
    case 'enrollment_recording':
    case 'submitting_enrollment':
    case 'requesting_verification':
    case 'verification_ready':
    case 'verification_microphone_request':
    case 'verification_recording':
    case 'submitting_verification':
    case 'error':
      return null;
    default:
      return assertNever(current);
  }
}

function renderEnrollmentMicrophoneRequest(
  current: Extract<DemoState, { kind: 'enrollment_microphone_request' }>,
): string {
  return `
    <div class="microphone-request" role="status">Allow microphone access</div>
    <h2>Get ready to read all four phrases</h2>
    <p class="instruction">Recording begins as soon as microphone access is ready. Keep this page visible and read from top to bottom.</p>
    ${renderPromptSequence(current.prompts, 'prompt-list prompt-list--active')}
  `;
}

function renderEnrollmentRecording(
  current: Extract<DemoState, { kind: 'enrollment_recording' }>,
): string {
  return `
    ${renderRecordingIndicator()}
    <h2>Speak now: read all four phrases</h2>
    <p class="instruction">Read naturally from top to bottom. Keep speaking until the countdown reaches zero.</p>
    ${renderPromptSequence(current.prompts, 'prompt-list prompt-list--active')}
    ${renderRecordingProgress(current.captureDurationMs)}
  `;
}

function renderVerificationMicrophoneRequest(
  current: Extract<DemoState, { kind: 'verification_microphone_request' }>,
): string {
  return `
    <div class="microphone-request" role="status">Allow microphone access</div>
    <h2>Get ready to read the fresh phrase</h2>
    <blockquote class="challenge-phrase">${escapeHtml(current.prompt)}</blockquote>
  `;
}

function renderVerificationRecording(
  current: Extract<DemoState, { kind: 'verification_recording' }>,
): string {
  return `
    ${renderRecordingIndicator()}
    <h2>Speak now: read this phrase once</h2>
    <blockquote class="challenge-phrase challenge-phrase--active">${escapeHtml(current.prompt)}</blockquote>
    ${renderRecordingProgress(current.captureDurationMs)}
  `;
}

function renderRecordingIndicator(): string {
  return `
    <div class="recording-indicator" role="status">
      <span class="recording-dot" aria-hidden="true"></span>
      <span>Microphone active</span>
    </div>
  `;
}

function renderRecordingProgress(durationMs: number): string {
  return `
    <div class="recording-progress">
      <div class="recording-timing">
        <strong data-recording-countdown>${formatDurationSeconds(durationMs)} seconds remaining</strong>
        <span>Recording stops automatically</span>
      </div>
      <progress data-recording-progress max="${durationMs}" value="0">0%</progress>
    </div>
  `;
}

function renderPendingState(): string {
  return '<div class="pending-indicator" role="status">Working…</div>';
}

function renderPromptSequence(prompts: readonly string[], className: string): string {
  return `<ol class="${escapeHtml(className)}">${prompts.map(renderPromptItem).join('')}</ol>`;
}

function enrollmentCaptureDurationMs(minimumCaptureMs: number): number {
  return Math.max(minimumCaptureMs, 18_000);
}

function formatDurationSeconds(durationMs: number): number {
  return Math.ceil(durationMs / 1000);
}

function beginEnrollmentRecording(): void {
  if (state.kind !== 'enrollment_microphone_request') return;
  const context = state;
  state = {
    kind: 'enrollment_recording',
    enrollmentId: context.enrollmentId,
    prompts: context.prompts,
    captureDurationMs: context.captureDurationMs,
    message: 'Speak now. Read every phrase aloud in order.',
  };
  render();
  startRecordingCountdown(context.captureDurationMs);
}

function beginVerificationRecording(): void {
  if (state.kind !== 'verification_microphone_request') return;
  const context = state;
  state = {
    kind: 'verification_recording',
    enrollmentId: context.enrollmentId,
    verificationId: context.verificationId,
    prompt: context.prompt,
    captureDurationMs: context.captureDurationMs,
    message: 'Speak now. Read the fresh phrase aloud once.',
  };
  render();
  startRecordingCountdown(context.captureDurationMs);
}

function startRecordingCountdown(durationMs: number): void {
  stopRecordingCountdown();
  recordingCountdown = { durationMs, endsAtMs: Date.now() + durationMs };
  updateRecordingCountdown();
  recordingCountdownTimerId = window.setInterval(updateRecordingCountdown, 250);
}

function stopRecordingCountdown(): void {
  if (recordingCountdownTimerId !== null) {
    window.clearInterval(recordingCountdownTimerId);
  }
  recordingCountdownTimerId = null;
  recordingCountdown = null;
}

function updateRecordingCountdown(): void {
  if (recordingCountdown === null) return;
  const remainingMs = Math.max(0, recordingCountdown.endsAtMs - Date.now());
  const elapsedMs = recordingCountdown.durationMs - remainingMs;
  const countdownElement = document.querySelector<HTMLElement>('[data-recording-countdown]');
  const progressElement = document.querySelector<HTMLProgressElement>('[data-recording-progress]');
  if (countdownElement !== null) {
    countdownElement.textContent = `${formatDurationSeconds(remainingMs)} seconds remaining`;
  }
  if (progressElement !== null) {
    progressElement.value = elapsedMs;
  }
}

function renderPromptItem(prompt: string): string {
  return `<li>${escapeHtml(prompt)}</li>`;
}

function errorState(error: unknown): Extract<DemoState, { kind: 'error' }> {
  return { kind: 'error', message: error instanceof Error ? error.message : String(error) };
}

function requireAppElement(): HTMLElement {
  const element = document.querySelector<HTMLElement>('#app');
  if (element === null) throw new Error('VoiceID demo root is missing');
  return element;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
