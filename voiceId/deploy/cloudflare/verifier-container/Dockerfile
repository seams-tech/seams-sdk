# syntax=docker/dockerfile:1.7
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.cache/huggingface \
    VOICEID_ECAPA_MODEL_CACHE=/app/.cache/speechbrain-spkrec-ecapa-voxceleb \
    VOICEID_VERIFIER_BACKEND=ecapa \
    VOICEID_VERIFIER_HOST=0.0.0.0 \
    VOICEID_VERIFIER_PORT=8797

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl ffmpeg libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

COPY verifier/pyproject.toml /app/verifier/pyproject.toml
COPY verifier/voiceid_verifier /app/verifier/voiceid_verifier

RUN python -m pip install --upgrade pip \
    && python -m pip install --index-url https://download.pytorch.org/whl/cpu "torch==2.6.*" "torchaudio==2.6.*" \
    && python -m pip install "/app/verifier[ecapa]"

ARG PRELOAD_ECAPA_MODEL=0
RUN if [ "$PRELOAD_ECAPA_MODEL" = "1" ]; then \
      VOICEID_VERIFIER_BACKEND=ecapa python -c "from voiceid_verifier.runtime import create_verifier_runtime_from_env; create_verifier_runtime_from_env()"; \
    fi

EXPOSE 8797

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8797/health', timeout=3).read()"

CMD ["python", "-m", "voiceid_verifier.app", "serve_http"]
