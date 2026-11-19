FROM python:3.11-slim
WORKDIR /app
# Non-root user for the runtime process (created before any app files land).
RUN groupadd -r alertlens && useradd -r -g alertlens -d /app alertlens
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/ ./api/
COPY scripts/ ./scripts/
COPY data/ ./data/
COPY benchmark.py .
# Train at BUILD time, not container start: the image ships a trained model
# and calibrated threshold, so `docker compose up` starts the API directly
# instead of retraining (and re-seeding) on every restart. ENV defaults to
# dev here, so the fail-fast API_KEY check in api/config.py does not fire
# at build time; the key is required at runtime (see docker-compose.yml).
RUN python scripts/train.py
RUN chown -R alertlens:alertlens /app
USER alertlens
ENV DATABASE_URL=postgresql+psycopg2://alertlens:alertlens@db:5432/alertlens
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=5s --retries=10 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=5)"
# Demo data is seeded only when SEED_DEMO=true (default false): a restarted
# container must not duplicate seed data or hide real ingested alerts.
CMD ["sh", "-c", "if [ \"$SEED_DEMO\" = \"true\" ]; then python scripts/seed.py; fi; exec uvicorn api.main:app --host 0.0.0.0 --port 8000"]
