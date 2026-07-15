const response = await fetch("http://127.0.0.1:8787/benchmark/activation", {
  method: "POST",
  body: new Uint8Array([0xa5]),
  signal: AbortSignal.timeout(5_000),
});
const body = await response.json();

if (response.status !== 400 || body.ok !== false || body.error_code !== "YAOS_AB_PUBLIC_BODY_NONEMPTY") {
  throw new Error(`public body reached the ceremony boundary: ${response.status} ${JSON.stringify(body)}`);
}

console.log(JSON.stringify({ status: response.status, body }));
