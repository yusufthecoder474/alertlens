.PHONY: install test test-backend test-frontend run seed train benchmark lint docker-up docker-down docker-smoke retrain

install:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
	cd frontend && npm install

test: test-backend test-frontend

test-backend:
	.venv/bin/python -m pytest tests/ -q --cov=api --cov-report=term

test-frontend:
	cd frontend && npm test

run:
	.venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

seed:
	.venv/bin/python scripts/seed.py

train:
	.venv/bin/python scripts/train.py

retrain:
	.venv/bin/python scripts/retrain.py

benchmark:
	.venv/bin/python benchmark.py

lint:
	.venv/bin/ruff check api scripts tests benchmark.py

docker-up:
	docker compose up --build -d --wait

docker-down:
	docker compose down -v

# Assert the composed stack end to end (needs `make docker-up` first and
# API_KEY set in the environment). See scripts/docker_smoke.py.
docker-smoke:
	python3 scripts/docker_smoke.py
