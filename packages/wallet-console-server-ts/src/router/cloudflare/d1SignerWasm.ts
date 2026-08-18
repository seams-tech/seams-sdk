export async function loadCloudflareSignerWasmModule() {
  return (await import('@seams/sdk-server/wasm/signer')).default;
}
