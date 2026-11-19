"""Guards for the Docker wiring (no Docker needed to run these).

The composed stack itself cannot run in this VM (no Docker daemon), so
these tests assert the wiring that the stack depends on: the nginx template
injects the key server-side, the browser bundle carries no key, compose
requires API_KEY with no fallback, the API image trains at build time and
runs as a non-root user with a healthcheck, and seeding is opt-in.
The live assertions live in scripts/docker_smoke.py (CI docker job).
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


def test_frontend_api_client_uses_same_origin_api_and_no_key():
    src = _read("frontend/src/api.js")
    assert '"/api"' in src
    assert "VITE_API_KEY" not in src
    assert "VITE_API_URL" not in src
    # The client must never *send* the key: no header is set anywhere in the
    # code (the docstring may mention that nginx injects it server-side).
    assert '"X-API-Key":' not in src
    assert "localhost:8000" not in src


def test_vite_dev_proxy_strips_api_prefix():
    cfg = _read("frontend/vite.config.js")
    assert '"/api"' in cfg and "localhost:8000" in cfg
    assert "rewrite" in cfg and "/^\\/api/" in cfg
    # The API requires X-API-Key, so the dev proxy must inject it
    # server-side (same job as nginx in Docker) — otherwise `npm run dev`
    # gets 401 on every request. The key comes from the dev server's env,
    # never from the browser bundle, and there is no hard-coded default:
    # `npm run dev` without API_KEY must fail with a clear error.
    assert '"X-API-Key"' in cfg and "process.env.API_KEY" in cfg
    assert "dev-api-key-change-me" not in cfg
    assert "throw new Error" in cfg and "API_KEY is required" in cfg
    # Same rule for the loader script: no hard-coded dev key anywhere.
    assert "dev-api-key-change-me" not in _read("scripts/load_csv.py")


def test_nginx_template_injects_key_server_side():
    tpl = _read("frontend/nginx.conf.template")
    assert "proxy_pass http://api:8000/" in tpl
    assert 'proxy_set_header X-API-Key "${API_KEY}"' in tpl
    assert "try_files" in tpl  # SPA fallback for the built app


def test_nginx_entrypoint_substitutes_only_api_key():
    entry = _read("frontend/docker-entrypoint.sh")
    assert "envsubst '$API_KEY'" in entry


def test_frontend_dockerfile_uses_nginx_templates():
    df = _read("frontend.Dockerfile")
    assert "nginx:1.27-alpine" in df
    assert "/etc/nginx/templates/default.conf.template" in df
    assert 'ENTRYPOINT ["/docker-entrypoint.sh"]' in df


def test_dockerignore_covers_secrets_and_caches():
    di = _read(".dockerignore")
    for entry in ["node_modules", "frontend/node_modules", "frontend/dist",
                  ".venv", "__pycache__", ".git", ".coverage", ".pytest_cache",
                  ".ruff_cache", "*.db", ".env",
                  # Dataset files must never enter an image: Docker/CI
                  # builds train on the synthetic generator, so they stay
                  # deterministic and small.
                  "data/unsw-nb15.csv", "data/unsw_alerts.csv"]:
        assert entry in di, f".dockerignore missing {entry}"


def test_backend_dockerfile_trains_at_build_runs_nonroot_and_healthchecks():
    df = _read("backend.Dockerfile")
    assert "RUN python scripts/train.py" in df
    assert "CMD [" in df and "scripts/train.py" not in df.split("CMD [", 1)[1]
    assert "USER alertlens" in df
    assert "HEALTHCHECK" in df and "/health" in df
    assert 'SEED_DEMO' in df and 'python scripts/seed.py' in df
    # Seed only when SEED_DEMO=true; the CMD must not run seed unconditionally.
    assert 'if [ \\"$SEED_DEMO\\" = \\"true\\" ]' in df


def test_compose_requires_api_key_and_healthy_api_dependency():
    compose = _read("docker-compose.yml")
    assert "API_KEY: ${API_KEY:?Set API_KEY in .env}" in compose
    assert "dev-api-key-change-me" not in compose
    # The DB port must not be published: it may appear only in a commented-out
    # line (the documented opt-in), never in an active ports mapping.
    active = [ln for ln in compose.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert not any("5432:5432" in ln for ln in active)
    assert "condition: service_healthy" in compose
    assert "healthcheck:" in compose and "/health" in compose
    assert "SEED_DEMO" in compose


def test_env_example_documents_compose_and_has_no_vite_key():
    env = _read(".env.example")
    assert "VITE_API_KEY" not in env
    assert "API_KEY" in env
    assert "SEED_DEMO" in env
