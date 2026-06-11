export type VoiceIdMicrophoneAccess =
  | {
      kind: 'granted';
      stream: MediaStream;
    }
  | {
      kind: 'denied';
      reason: 'permission_denied' | 'browser_unsupported';
    };

export async function requestVoiceIdMicrophone(): Promise<VoiceIdMicrophoneAccess> {
  if (!navigator.mediaDevices?.getUserMedia) {
    return { kind: 'denied', reason: 'browser_unsupported' };
  }

  try {
    return {
      kind: 'granted',
      stream: await navigator.mediaDevices.getUserMedia({ audio: true }),
    };
  } catch {
    return { kind: 'denied', reason: 'permission_denied' };
  }
}

export function stopVoiceIdMicrophone(stream: MediaStream): void {
  for (const track of stream.getTracks()) {
    track.stop();
  }
}
