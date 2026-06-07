# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

COPY app ./app

# Non-root
RUN useradd -u 1000 -m appuser
USER appuser

EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
