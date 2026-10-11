import os
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy.orm import Session
import jwt
from .core import Base, engine, SessionLocal, User, Note, hash_pw, verify_pw, make_token, read_token, cache

Base.metadata.create_all(engine)
app = FastAPI(title="Notes API", version="1.0",
              description="JWT auth, per-user notes (PostgreSQL), Redis-cached reads, role-based admin. Click **Authorize** after logging in.")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ---------- schemas ----------
class RegisterIn(BaseModel):
    email: EmailStr; password: str = Field(min_length=8, max_length=72)
class TokenOut(BaseModel):
    access_token: str; token_type: str = "bearer"
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True); id: int; email: EmailStr; role: str
class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=200); content: str = ""
class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200); content: Optional[str] = None
class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True); id: int; title: str; content: str

# ---------- deps ----------
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    err = HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    try: uid = read_token(token)
    except (jwt.PyJWTError, ValueError): raise err
    user = db.get(User, uid)
    if not user: raise err
    return user

def admin_only(user: User = Depends(current_user)) -> User:
    if user.role != "admin": raise HTTPException(403, "Admin only")
    return user

# ---------- auth ----------
@app.post("/auth/register", response_model=UserOut, status_code=201, tags=["auth"])
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.query(User).filter_by(email=email).first(): raise HTTPException(409, "Email already registered")
    role = "admin" if email == os.getenv("ADMIN_EMAIL", "").lower() else "user"
    user = User(email=email, hashed_password=hash_pw(body.password), role=role)
    db.add(user); db.commit(); db.refresh(user); return user

@app.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=form.username.lower()).first()
    if not user or not verify_pw(form.password, user.hashed_password): raise HTTPException(401, "Incorrect email or password")
    return {"access_token": make_token(user.id)}

@app.get("/me", response_model=UserOut, tags=["auth"])
def me(user: User = Depends(current_user)): return user

# ---------- notes (owner-scoped; list is cached, writes invalidate) ----------
def _own(db, user, note_id):
    n = db.query(Note).filter_by(id=note_id, owner_id=user.id).first()
    if not n: raise HTTPException(404, "Note not found")      # 404 (not 403) so ids of other users' notes aren't leaked
    return n

@app.post("/notes", response_model=NoteOut, status_code=201, tags=["notes"])
def create_note(body: NoteIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = Note(**body.model_dump(), owner_id=user.id); db.add(n); db.commit(); db.refresh(n)
    cache.delete_prefix(f"notes:{user.id}:"); return n

@app.get("/notes", response_model=List[NoteOut], tags=["notes"])
def list_notes(response: Response, skip: int = 0, limit: int = 20, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = f"notes:{user.id}:{skip}:{limit}"
    hit = cache.get(key)
    response.headers["X-Cache"] = f"HIT ({cache.backend})" if hit is not None else f"MISS ({cache.backend})"
    if hit is not None: return hit
    rows = [NoteOut.model_validate(n).model_dump() for n in
            db.query(Note).filter_by(owner_id=user.id).order_by(Note.id.desc()).offset(skip).limit(min(limit, 100)).all()]
    cache.set(key, rows, ttl=60); return rows

@app.get("/notes/{note_id}", response_model=NoteOut, tags=["notes"])
def get_note(note_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)): return _own(db, user, note_id)

@app.patch("/notes/{note_id}", response_model=NoteOut, tags=["notes"])
def update_note(note_id: int, body: NoteUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = _own(db, user, note_id)
    for k, v in body.model_dump(exclude_unset=True).items(): setattr(n, k, v)
    db.commit(); db.refresh(n); cache.delete_prefix(f"notes:{user.id}:"); return n

@app.delete("/notes/{note_id}", status_code=204, tags=["notes"])
def delete_note(note_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(_own(db, user, note_id)); db.commit(); cache.delete_prefix(f"notes:{user.id}:")

# ---------- admin ----------
@app.get("/admin/users", response_model=List[UserOut], tags=["admin"])
def all_users(_: User = Depends(admin_only), db: Session = Depends(get_db)): return db.query(User).all()

@app.get("/health", tags=["ops"])
def health(): return {"status": "ok", "cache": cache.backend}
