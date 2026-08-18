export async function loadCloudflareSignerWasmModule() {
  return (await import('@seams/wallet-server/wasm/signer')).default;
}
