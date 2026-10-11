# Notes API - JWT auth, PostgreSQL, Redis cache, pytest, Swagger
FastAPI + SQLAlchemy. Passwords hashed with bcrypt, short-lived JWT access tokens, owner-scoped resources,
role-based admin route, Redis-cached list endpoint with write-invalidation (`X-Cache: HIT/MISS` header shows it working).

## Fastest: run the tests (no server, no DB, no Redis needed)
    pip install -r requirements.txt
    pytest -v

## Run locally (SQLite + in-memory cache by default)
    python -m uvicorn app.main:app --port 8000      # keep this terminal open
    # open http://localhost:8000/docs  -> Register -> Login -> click Authorize -> try /notes

## Full stack with PostgreSQL + Redis
    docker compose up --build                       # then http://localhost:8000/docs

## Config (env vars)
DATABASE_URL, REDIS_URL, SECRET_KEY (set a long random one in production), TOKEN_MINUTES, ADMIN_EMAIL (that email becomes admin on register)

## Known limits (good interview talking points)
No refresh tokens / token revocation, no login rate limiting, tables via create_all (use Alembic migrations in production),
cache invalidation is per-user prefix (fine at this scale).
