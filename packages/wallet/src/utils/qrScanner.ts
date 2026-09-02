import {
  parseQrLinkedDeviceSessionTextV5,
  type QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import jsQR from 'jsqr';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../core/types/linkDevice';
import { validateQrLinkedDeviceSessionPayloadV5 } from '../SeamsWeb/operations/devices/scanDevice';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';

// ===========================
// TYPES AND INTERFACES
// ===========================

export interface ScanQRCodeFlowOptions {
  cameraId?: string;
  cameraConfigs?: {
    facingMode?: 'user' | 'environment';
    width?: number;
    height?: number;
  };
  timeout?: number; // in milliseconds, default 60000
}

export interface ScanQRCodeFlowEvents {
  onEvent?: (event: LinkDeviceFlowEvent) => void;
  onQRDetected?: (qrData: QrLinkedDeviceSessionPayloadV5) => void;
  onError?: (error: Error) => void;
  onCameraReady?: (stream: MediaStream) => void;
  onScanProgress?: (duration: number) => void; // Called periodically during scanning
}

export enum ScanQRCodeFlowState {
  IDLE = 'idle',
  INITIALIZING = 'initializing',
  SCANNING = 'scanning',
  SUCCESS = 'success',
  ERROR = 'error',
  CANCELLED = 'cancelled',
}

// ===========================
// SCANQRCODEFLOW CLASS
// ===========================

/**
 * ScanQRCodeFlow - Encapsulates QR code scanning lifecycle
 * Can be used in both React (useQRCamera) and non-React (SeamsWeb) contexts
 */
export class ScanQRCodeFlow {
  private state: ScanQRCodeFlowState = ScanQRCodeFlowState.IDLE;
  private mediaStream: MediaStream | null = null;
  private video: HTMLVideoElement | null = null;
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private animationId: number | null = null;
  private timeoutId: NodeJS.Timeout | null = null;
  private progressIntervalId: NodeJS.Timeout | null = null;
  private scanStartTime: number = 0;
  private currentError: Error | null = null;
  private detectedQRData: QrLinkedDeviceSessionPayloadV5 | null = null;
  private startGeneration = 0;

  constructor(
    private options: ScanQRCodeFlowOptions = {},
    private events: ScanQRCodeFlowEvents = {},
  ) {
    this.canvas = document.createElement('canvas');
    const ctx = this.canvas.getContext('2d');
    if (!ctx) {
      throw new Error('Unable to get canvas 2D context');
    }
    this.ctx = ctx;
  }

  /**
   * Get current flow state
   */
  getState(): {
    state: ScanQRCodeFlowState;
    isScanning: boolean;
    scanDuration: number;
    error: Error | null;
    qrData: QrLinkedDeviceSessionPayloadV5 | null;
  } {
    return {
      state: this.state,
      isScanning: this.state === ScanQRCodeFlowState.SCANNING,
      scanDuration: this.scanStartTime ? Date.now() - this.scanStartTime : 0,
      error: this.currentError,
      qrData: this.detectedQRData,
    };
  }

  /**
   * Start scanning for QR codes
   */
  async startQRScanner(): Promise<void> {
    if (
      this.state !== ScanQRCodeFlowState.IDLE &&
      this.state !== ScanQRCodeFlowState.ERROR &&
      this.state !== ScanQRCodeFlowState.CANCELLED
    ) {
      return; // Already running
    }

    // Starting the camera spans two awaits the user can close the scanner
    // across. Anything stopping or restarting the flow bumps this, so a start
    // that lost the race can tell the difference between "the camera failed"
    // and "nobody is waiting for this camera any more".
    const generation = ++this.startGeneration;

    this.setState(ScanQRCodeFlowState.INITIALIZING);
    this.currentError = null;
    this.detectedQRData = null;

    try {
      // Build camera constraints
      const constraints = this.buildCameraConstraints();

      // Get camera stream
      const mediaStream = await navigator.mediaDevices.getUserMedia(constraints);

      // Cancelled while the permission prompt or camera warm-up was pending:
      // cleanup() already ran and never saw this stream, so release it here or
      // the camera light stays on with nothing scanning.
      if (this.isSupersededStart(generation)) {
        mediaStream.getTracks().forEach((track) => track.stop());
        return;
      }
      this.mediaStream = mediaStream;

      // Create video element if not provided externally
      if (!this.video) {
        this.video = document.createElement('video');
        this.video.playsInline = true;
        this.video.muted = true;
      }

      this.video.srcObject = this.mediaStream;
      await this.video.play();
      if (this.isSupersededStart(generation)) return;

      // Notify camera is ready
      this.events.onCameraReady?.(this.mediaStream);

      this.setState(ScanQRCodeFlowState.SCANNING);
      this.scanStartTime = Date.now();

      // Start progress tracking
      this.startProgressTracking();

      // Set timeout if specified
      const timeout = this.options.timeout ?? 60000;
      if (timeout > 0) {
        this.timeoutId = setTimeout(() => {
          this.handleError(
            new Error(
              `No QR code was found in ${Math.round(timeout / 1000)} seconds. ` +
                'Center the code in the frame and try again.',
            ),
          );
        }, timeout);
      }

      // Start scanning loop
      this.scanFrame();
    } catch (error: unknown) {
      // Closing the scanner tears the video down under the pending play(),
      // which rejects with an AbortError. The user chose that, so it is a
      // cancellation, not a camera failure worth a message. Whoever superseded
      // this start owns the flow now, so leave its state and stream alone.
      if (this.isSupersededStart(generation)) return;
      if (isScannerCancellationError(error)) {
        this.setState(ScanQRCodeFlowState.CANCELLED);
        this.cleanup();
        return;
      }
      this.handleError(new Error(cameraAccessFailureMessage(error)));
    }
  }

  /**
   * Stop scanning and cleanup resources
   *
   * This method stops the scanning process and cleans up all internal resources.
   * For React contexts with external video elements, use destroy() instead.
   */
  stop(): void {
    this.startGeneration += 1;
    this.setState(ScanQRCodeFlowState.CANCELLED);
    this.cleanup();
  }

  /**
   * Attach an external video element (for React contexts)
   */
  attachVideoElement(video: HTMLVideoElement): void {
    this.video = video;
    if (this.mediaStream && this.state === ScanQRCodeFlowState.SCANNING) {
      this.video.srcObject = this.mediaStream;
      // Detaching or stopping before this settles rejects it; the scan loop
      // reads readyState, so a lost play() needs no report of its own.
      void this.video.play().catch(() => {});
    }
  }

  /**
   * Detach the video element
   */
  detachVideoElement(): void {
    if (this.video) {
      this.video.srcObject = null;
    }
    this.video = null;
  }

  /**
   * Switch to a different camera
   */
  async switchCamera(cameraId: string): Promise<void> {
    const wasScanning = this.state === ScanQRCodeFlowState.SCANNING;
    if (wasScanning) {
      this.stop();
    }

    this.options.cameraId = cameraId;

    if (wasScanning) {
      await this.startQRScanner();
    }
  }

  /**
   * Get available video devices
   */
  async getAvailableCameras(): Promise<MediaDeviceInfo[]> {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.filter((device) => device.kind === 'videoinput');
    } catch (error) {
      console.error('Error enumerating cameras:', error);
      throw new Error('Failed to access camera devices');
    }
  }

  /**
   * Get the current media stream (for external video elements)
   */
  getMediaStream(): MediaStream | null {
    return this.mediaStream;
  }

  // Private methods

  private setState(newState: ScanQRCodeFlowState): void {
    this.state = newState;
  }

  /** True once this start attempt was cancelled or replaced by a later one. */
  private isSupersededStart(generation: number): boolean {
    return generation !== this.startGeneration;
  }

  private buildCameraConstraints(): MediaStreamConstraints {
    const constraints: MediaStreamConstraints = {
      video: {
        deviceId: this.options.cameraId || undefined,
        width: { ideal: 720, min: 480 },
        height: { ideal: 720, min: 480 },
        aspectRatio: { ideal: 1.0 },
        facingMode: this.options.cameraId ? undefined : this.options.cameraConfigs?.facingMode,
      },
    };

    // Override with custom width/height if provided
    if (this.options.cameraConfigs?.width || this.options.cameraConfigs?.height) {
      const videoConstraints = constraints.video as MediaTrackConstraints;
      if (this.options.cameraConfigs.width) {
        videoConstraints.width = { ideal: this.options.cameraConfigs.width, min: 480 };
      }
      if (this.options.cameraConfigs.height) {
        videoConstraints.height = { ideal: this.options.cameraConfigs.height, min: 480 };
      }
    }

    return constraints;
  }

  private startProgressTracking(): void {
    this.progressIntervalId = setInterval(() => {
      if (this.state === ScanQRCodeFlowState.SCANNING) {
        const duration = Date.now() - this.scanStartTime;
        this.events.onScanProgress?.(duration);
      }
    }, 100); // Update every 100ms
  }

  private async scanFrame(): Promise<void> {
    if (this.state !== ScanQRCodeFlowState.SCANNING || !this.video || !this.mediaStream) {
      return;
    }

    try {
      // Check if video is ready
      if (this.video.readyState === this.video.HAVE_ENOUGH_DATA) {
        // Draw video frame to canvas
        this.canvas.width = this.video.videoWidth;
        this.canvas.height = this.video.videoHeight;
        this.ctx.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);

        // Scan for QR code
        const imageData = this.ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
        const qrData = await this.scanQRFromImageData(imageData);

        if (qrData) {
          const parsedData = this.parseAndValidateQRData(qrData);
          this.handleSuccess(parsedData);
          return;
        }
      }
    } catch (error: any) {
      // Fail the scan on validation or frame errors
      this.handleError(error instanceof Error ? error : new Error(String(error)));
      return;
    }

    // Schedule next frame
    if (this.state === ScanQRCodeFlowState.SCANNING) {
      this.animationId = requestAnimationFrame(() => this.scanFrame());
    }
  }

  private async scanQRFromImageData(imageData: ImageData): Promise<string | null> {
    return scanQRFromImageData(imageData);
  }

  private parseAndValidateQRData(qrData: string): QrLinkedDeviceSessionPayloadV5 {
    return parseAndValidateQRData(qrData);
  }

  private handleSuccess(qrData: QrLinkedDeviceSessionPayloadV5): void {
    this.setState(ScanQRCodeFlowState.SUCCESS);
    this.detectedQRData = qrData;
    this.cleanup();
    this.events.onQRDetected?.(qrData);
  }

  private handleError(error: Error): void {
    this.setState(ScanQRCodeFlowState.ERROR);
    this.currentError = error;
    this.cleanup();
    this.events.onError?.(error);
  }

  private cleanup(): void {
    // Stop animation frame
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }

    // Clear timeout
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }

    // Stop progress tracking
    if (this.progressIntervalId) {
      clearInterval(this.progressIntervalId);
      this.progressIntervalId = null;
    }

    // MediaStream Cleanup: Stop all tracks and clear all video references
    // This ensures camera light turns off regardless of how the video element is managed
    if (this.mediaStream) {
      this.mediaStream.getTracks().forEach((track) => track.stop());
      this.mediaStream = null;
    }

    // Clear all video sources to ensure no lingering MediaStream references
    if (this.video) {
      this.video.srcObject = null;
    }
  }
}

/**
 * Does this rejection mean the scanner went away, rather than the camera
 * failing?
 *
 * Clearing `srcObject` or stopping the tracks under a pending `play()` rejects
 * it with an `AbortError` whose message is about the media element ("The play()
 * request was interrupted by a new load request"), not about the user. Safari
 * and Firefox word it differently, so match the name first and keep the text
 * check only as a fallback for browsers that use a bare `Error`.
 */
export function isScannerCancellationError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.name === 'AbortError') return true;
  return /interrupted by|request was interrupted|media was removed/i.test(error.message);
}

/**
 * A sentence to show someone whose camera genuinely did not start.
 *
 * `getUserMedia` reports the cause in `name`; its `message` is browser-authored
 * debugging text ending in a goo.gl link, which is not something to put in
 * front of a user.
 */
export function cameraAccessFailureMessage(error: unknown): string {
  switch (error instanceof Error ? error.name : '') {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'Camera access was blocked. Allow camera access in your browser, then scan again.';
    case 'NotFoundError':
    case 'DevicesNotFoundError':
      return 'No camera was found on this device.';
    case 'NotReadableError':
    case 'TrackStartError':
      return 'The camera is being used by another app. Close it, then scan again.';
    case 'OverconstrainedError':
    case 'ConstraintNotSatisfiedError':
      return 'This camera does not support the requested video size.';
    default:
      return 'The camera could not be started. Check your camera, then scan again.';
  }
}

// ===========================
// CONVENIENCE FUNCTIONS
// ===========================

/**
 * Scan QR code from file with lazy loading
 */
export async function scanQRCodeFromFile(file: File): Promise<QrLinkedDeviceSessionPayloadV5> {
  // Setup canvas
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  if (!ctx) throw createQRError('Unable to get canvas 2D context');

  // Load and process image
  const dataUrl = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        resolve(e.target.result as string);
      } else {
        reject(createQRError('Failed to read file'));
      }
    };
    reader.onerror = () => reject(createQRError('Failed to read file'));
    reader.readAsDataURL(file);
  });

  // Process image
  const img = await new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(createQRError('Failed to load image file'));
    image.src = dataUrl;
  });

  // Scan QR code using shared logic
  canvas.width = img.width;
  canvas.height = img.height;
  ctx.drawImage(img, 0, 0);

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const qrData = await scanQRFromImageData(imageData);

  if (!qrData) {
    throw createQRError('No QR code found in image');
  }

  return parseAndValidateQRData(qrData);
}

// ===========================
// UTILITY FUNCTIONS
// ===========================

/**
 * Enumerate available video input devices
 */
export async function enumerateVideoDevices(): Promise<MediaDeviceInfo[]> {
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.filter((device) => device.kind === 'videoinput');
  } catch (error) {
    console.error('Error enumerating cameras:', error);
    throw new Error('Failed to access camera devices');
  }
}

/**
 * Detect if a camera is front-facing based on its label
 */
export function detectFrontCamera(camera: MediaDeviceInfo): boolean {
  const label = camera.label.toLowerCase();
  return (
    label.includes('front') ||
    label.includes('user') ||
    label.includes('selfie') ||
    label.includes('facetime') ||
    label.includes('facing front')
  );
}

/**
 * Detect camera facing mode from media stream settings
 */
export function detectCameraFacingMode(stream: MediaStream): boolean {
  const videoTrack = stream.getVideoTracks()[0];
  if (videoTrack) {
    const settings = videoTrack.getSettings();
    return settings.facingMode === 'user';
  }
  return false;
}

// ===========================
// PRIVATE HELPER FUNCTIONS
// ===========================

async function scanQRFromImageData(imageData: ImageData): Promise<string | null> {
  const code = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: 'dontInvert',
  });
  return code ? code.data : null;
}

function parseAndValidateQRData(qrData: string): QrLinkedDeviceSessionPayloadV5 {
  if (qrData.startsWith('http')) {
    throw new Error('QR code contains a URL, not device linking data');
  }
  if (qrData.includes('ed25519:')) {
    throw new Error('QR code contains a NEAR key, not device linking data');
  }
  return validateQrLinkedDeviceSessionPayloadV5(parseQrLinkedDeviceSessionTextV5(qrData));
}

function createQRError(message: string): DeviceLinkingError {
  return new DeviceLinkingError(message, DeviceLinkingErrorCode.INVALID_QR_DATA, 'authorization');
}
