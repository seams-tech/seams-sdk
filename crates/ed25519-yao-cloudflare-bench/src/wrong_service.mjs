const BENCHMARK_PATH = "/benchmark/activation";

export default {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || path !== BENCHMARK_PATH) {
      return new Response("wrong-service endpoint not found", { status: 404 });
    }
    console.log(JSON.stringify({
      event: "ed25519_yao_wrong_service_invoked",
      benchmark_only: true,
    }));
    return Response.json(
      { ok: false, benchmark_only: true, service: "fixed-wrong-service" },
      { status: 418, headers: { "cache-control": "no-store" } },
    );
  },
};
