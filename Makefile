.PHONY: bff-install bff-run bff-test bff-fmt bff-lint web-install web-dev web-build web-typecheck up down

# --- BFF (FastAPI) ---
bff-install:
	cd bff && python -m venv .venv && .venv/bin/pip install -e ".[dev]"

bff-run:
	cd bff && .venv/bin/uvicorn app.main:app --reload --port 8090

bff-test:
	cd bff && .venv/bin/pytest -q

bff-fmt:
	cd bff && .venv/bin/black .

bff-lint:
	cd bff && .venv/bin/flake8 app tests --max-line-length=120

# --- Web (React + Vite) ---
web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

web-typecheck:
	cd web && npm run typecheck

# --- Compose ---
up:
	docker compose up --build

down:
	docker compose down
