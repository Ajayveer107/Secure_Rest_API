"""DB models, password hashing, JWT, and a Redis-or-memory cache."""
import os, time, json
from datetime import datetime, timedelta, timezone
import bcrypt, jwt
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGO, TOKEN_MINUTES = "HS256", int(os.getenv("TOKEN_MINUTES", "30"))
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")   # postgres: postgresql+psycopg2://user:pw@host/db
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False); role = Column(String(20), default="user")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True); title = Column(String(200), nullable=False); content = Column(Text, default="")
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# ---- security ----
def hash_pw(pw: str) -> str: return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def verify_pw(pw: str, h: str) -> bool: return bcrypt.checkpw(pw.encode(), h.encode())
def make_token(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id), "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)}, SECRET_KEY, ALGO)
def read_token(tok: str) -> int:
    return int(jwt.decode(tok, SECRET_KEY, algorithms=[ALGO])["sub"])

# ---- cache: Redis if REDIS_URL is set and reachable, else in-process dict with TTL ----
class Cache:
    def __init__(self):
        self.r, self.mem = None, {}
        if os.getenv("REDIS_URL"):
            try:
                import redis; self.r = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True); self.r.ping()
            except Exception: self.r = None
    @property
    def backend(self): return "redis" if self.r else "memory"
    def get(self, k):
        if self.r: v = self.r.get(k); return json.loads(v) if v else None
        v = self.mem.get(k); return v[1] if v and v[0] > time.time() else None
    def set(self, k, val, ttl=60):
        if self.r: self.r.setex(k, ttl, json.dumps(val))
        else: self.mem[k] = (time.time() + ttl, val)
    def delete_prefix(self, prefix):
        if self.r: [self.r.delete(k) for k in self.r.scan_iter(prefix + "*")]
        else: [self.mem.pop(k) for k in [k for k in self.mem if k.startswith(prefix)]]
cache = Cache()
