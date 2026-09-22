PY=.venv/bin/python
.PHONY: install backend frontend test demo clean-demo train
install:
	python3.13 -m venv .venv
	$(PY) -m pip install -r requirements.lock -e '.[dev]'
	cd frontend && npm ci
backend:
	$(PY) -m uvicorn backend.api.main:app --host 127.0.0.1 --port 18760
frontend:
	cd frontend && npm run dev -- --host 127.0.0.1
test: train
	$(PY) -m pytest -q
	$(PY) -m ruff check .
	$(PY) -m mypy backend training scripts
	cd frontend && npm run typecheck && npm run lint && npm test -- --run && npm run build
train:
	$(PY) -m training.train
demo: train
	$(PY) -m scripts.demo
clean-demo:
	$(PY) -m scripts.clean_demo

# Dependencies are installed explicitly by make install; release-check stays offline.
# Use make release-check RELEASE_NPM_CI=1 for an explicit clean lockfile install.
RELEASE_NPM_CI ?= 0
.PHONY: release-check
release-check:
	$(PY) -m scripts.check_model
	$(PY) -m pytest -q
	$(PY) -m compileall -q backend training scripts
	$(PY) -m ruff check .
	$(PY) -m mypy backend training scripts
	$(PY) -m scripts.demo
	@if [ "$(RELEASE_NPM_CI)" = "1" ]; then cd frontend && npm ci; fi
	cd frontend && npm run typecheck && npm run lint && npm test -- --run && npm run build
