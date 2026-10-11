import jwt
from datetime import datetime, timedelta, timezone
from app.core import SECRET_KEY, ALGO

def test_register_login_me(client, auth):
    h = auth(); r = client.get("/me", headers=h)
    assert r.status_code == 200 and r.json()["email"] == "a@example.com" and r.json()["role"] == "user"
    assert "password" not in r.text

def test_duplicate_and_validation(client):
    body = {"email": "a@example.com", "password": "password123"}
    assert client.post("/auth/register", json=body).status_code == 201
    assert client.post("/auth/register", json=body).status_code == 409
    assert client.post("/auth/register", json={"email": "bad", "password": "password123"}).status_code == 422
    assert client.post("/auth/register", json={"email": "b@example.com", "password": "short"}).status_code == 422

def test_wrong_password(client, auth):
    auth(); assert client.post("/auth/login", data={"username": "a@example.com", "password": "nope-nope"}).status_code == 401

def test_protected_routes_need_valid_token(client):
    assert client.get("/notes").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    expired = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, SECRET_KEY, ALGO)
    assert client.get("/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401

def test_notes_crud(client, auth):
    h = auth(); n = client.post("/notes", json={"title": "t1", "content": "c"}, headers=h).json()
    assert client.get(f"/notes/{n['id']}", headers=h).json()["title"] == "t1"
    assert client.patch(f"/notes/{n['id']}", json={"title": "new"}, headers=h).json() == {"id": n["id"], "title": "new", "content": "c"}
    assert client.delete(f"/notes/{n['id']}", headers=h).status_code == 204
    assert client.get(f"/notes/{n['id']}", headers=h).status_code == 404

def test_users_cannot_touch_each_others_notes(client, auth):
    h1, h2 = auth("a@example.com"), auth("b@example.com")
    nid = client.post("/notes", json={"title": "secret"}, headers=h1).json()["id"]
    assert client.get(f"/notes/{nid}", headers=h2).status_code == 404
    assert client.delete(f"/notes/{nid}", headers=h2).status_code == 404
    assert client.get("/notes", headers=h2).json() == []

def test_cache_hit_and_invalidation(client, auth):
    h = auth(); client.post("/notes", json={"title": "x"}, headers=h)
    assert client.get("/notes", headers=h).headers["X-Cache"].startswith("MISS")
    assert client.get("/notes", headers=h).headers["X-Cache"].startswith("HIT")
    client.post("/notes", json={"title": "y"}, headers=h)            # write invalidates
    r = client.get("/notes", headers=h)
    assert r.headers["X-Cache"].startswith("MISS") and len(r.json()) == 2

def test_admin_role(client, auth):
    assert client.get("/admin/users", headers=auth("a@example.com")).status_code == 403
    admin = auth("boss@example.com")
    assert client.get("/me", headers=admin).json()["role"] == "admin"
    assert len(client.get("/admin/users", headers=admin).json()) == 2

def test_swagger_docs_available(client):
    assert client.get("/docs").status_code == 200 and "/auth/login" in client.get("/openapi.json").json()["paths"]
