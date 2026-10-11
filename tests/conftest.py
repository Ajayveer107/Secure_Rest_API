import os, sys, pathlib, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/test.db"
os.environ["ADMIN_EMAIL"] = "boss@example.com"
os.environ.pop("REDIS_URL", None)
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core import Base, engine, cache

@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine); Base.metadata.create_all(engine); cache.mem.clear(); yield

@pytest.fixture
def client(): return TestClient(app)

@pytest.fixture
def auth(client):
    def _make(email="a@example.com", pw="password123"):
        client.post("/auth/register", json={"email": email, "password": pw})
        t = client.post("/auth/login", data={"username": email, "password": pw}).json()["access_token"]
        return {"Authorization": f"Bearer {t}"}
    return _make
