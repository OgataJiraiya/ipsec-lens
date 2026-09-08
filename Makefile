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
test:
	$(PY) -m pytest -q
	$(PY) -m ruff check backend training scripts
	$(PY) -m mypy backend
	cd frontend && npm run typecheck && npm run lint && npm test -- --run && npm run build
train:
	$(PY) -m training.train
demo: train
	$(PY) -m scripts.demo
clean-demo:
	$(PY) -m scripts.clean_demo
