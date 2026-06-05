export function shouldPrewarmBrowserWorkers(workerBaseOrigin: string): boolean {
  if (typeof window === 'undefined' || typeof window.Worker === 'undefined') return false;
  if (workerBaseOrigin && workerBaseOrigin !== window.location.origin) return false;
  return true;
}
