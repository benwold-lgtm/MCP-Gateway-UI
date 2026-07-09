# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY pyproject.toml ./
# The redis extra backs the shared session store (SESSION_REDIS_URL) — a few hundred
# kB, baked in so the same image serves single-replica lite and multi-replica K8s.
RUN pip install --upgrade pip && pip install ".[redis]"

COPY app ./app

# Non-root. Also pre-create + chown /data: it's unused unless a deployment mounts a volume
# there (e.g. the lite compose's BFF_STATE_DIR), but Docker seeds a brand-new named volume
# by copying whatever the image has at that path, ownership included — a path absent from
# the image entirely gets a bare root-owned directory instead, which appuser can't write to.
RUN useradd -u 1000 -m appuser && mkdir -p /data && chown -R appuser:appuser /data
USER appuser

EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
