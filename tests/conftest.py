"""Test setup: temp SQLite DB, API key auth, rate-limit reset per test."""
import os
import sys
import tempfile

os.environ["API_KEY"] = "test-key"
# Respect a DATABASE_URL already set by the caller (CI sets Postgres 17);
# only then do the Postgres-backed tests run instead of being skipped.
# Locally, with no DATABASE_URL set, tests use a throwaway SQLite file.
os.environ.setdefault("DATABASE_URL", "sqlite:///" + tempfile.mktemp(suffix=".db"))
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.database import Base, SessionLocal, engine, get_db  # noqa: E402
from api.main import app  # noqa: E402
from api.security import reset_rate_limit  # noqa: E402

HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture(autouse=True)
def _fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    reset_rate_limit()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def client():
    def _override():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
