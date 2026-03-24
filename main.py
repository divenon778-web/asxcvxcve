from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, constr
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_database_url(raw_url: str) -> str:
    # Render Postgres URLs often start with postgres://, convert for SQLAlchemy.
    if raw_url.startswith("postgres://"):
        return raw_url.replace("postgres://", "postgresql+psycopg2://", 1)
    return raw_url


DATABASE_URL = parse_database_url(os.getenv("DATABASE_URL", "sqlite:///./keys.db"))
KEY_HASH_SECRET = os.getenv("KEY_HASH_SECRET", "CHANGE_THIS_IN_PROD")
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "CHANGE_THIS_TOO")
VERIFY_RATE_LIMIT = int(os.getenv("VERIFY_RATE_LIMIT", "30"))
VERIFY_WINDOW_SECONDS = int(os.getenv("VERIFY_WINDOW_SECONDS", "60"))
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()]

if KEY_HASH_SECRET in {"CHANGE_THIS_IN_PROD", "", None}:
    print("[WARN] KEY_HASH_SECRET is default/weak. Set a long random value in production.")
if ADMIN_API_TOKEN in {"CHANGE_THIS_TOO", "", None}:
    print("[WARN] ADMIN_API_TOKEN is default/weak. Set a long random value in production.")

is_sqlite = DATABASE_URL.startswith("sqlite")
engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if is_sqlite else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


class PlanType(str, Enum):
    trial = "trial"
    monthly = "monthly"
    lifetime = "lifetime"


class LicenseKey(Base):
    __tablename__ = "license_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    key_hint: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    duration_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    first_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    bind_to_device: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    bound_device_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class VerifyKeyRequest(BaseModel):
    key: constr(min_length=12, max_length=256)
    device_id: Optional[constr(min_length=4, max_length=256)] = None


class VerifyKeyResponse(BaseModel):
    valid: bool
    plan: Optional[PlanType] = None
    expires_at: Optional[datetime] = None
    message: str


class GenerateKeysRequest(BaseModel):
    plan: PlanType
    quantity: int = Field(default=1, ge=1, le=500)
    note: Optional[str] = Field(default=None, max_length=500)
    bind_to_device: bool = True


class GeneratedKeyItem(BaseModel):
    id: str
    key: str
    plan: PlanType
    duration_days: Optional[int]
    bind_to_device: bool
    created_at: datetime


class GenerateKeysResponse(BaseModel):
    keys: list[GeneratedKeyItem]


class RevokeKeyRequest(BaseModel):
    key: Optional[str] = None
    key_id: Optional[str] = None


class KeyMetaResponse(BaseModel):
    id: str
    key_hint: str
    plan: PlanType
    duration_days: Optional[int]
    created_at: datetime
    first_used_at: Optional[datetime]
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    is_active: bool
    revoked_at: Optional[datetime]
    bind_to_device: bool
    note: Optional[str]


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def normalize_key(raw_key: str) -> str:
    return "".join(raw_key.strip().upper().split())


def hmac_sha256(value: str) -> str:
    return hmac.new(KEY_HASH_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def key_hash(raw_key: str) -> str:
    return hmac_sha256(normalize_key(raw_key))


def device_hash(device_id: str) -> str:
    return hmac_sha256(device_id.strip())


def require_admin(authorization: Optional[str] = Header(default=None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing admin auth.")
    token = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(token, ADMIN_API_TOKEN):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin auth.")


def random_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    chunk = lambda n: "".join(secrets.choice(alphabet) for _ in range(n))
    # Full key is verified via HMAC hash of the full string, not by prefix.
    return f"LUNA-{chunk(6)}-{chunk(6)}-{chunk(6)}-{chunk(6)}"


def plan_duration_days(plan: PlanType) -> Optional[int]:
    if plan == PlanType.trial:
        return 1
    if plan == PlanType.monthly:
        return 30
    return None


class InMemoryRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            active = [ts for ts in self._events.get(key, []) if now - ts < self.window_seconds]
            if len(active) >= self.max_attempts:
                retry_after = max(1, int(self.window_seconds - (now - active[0])))
                self._events[key] = active
                return False, retry_after
            active.append(now)
            self._events[key] = active
            return True, 0


verify_rate_limiter = InMemoryRateLimiter(VERIFY_RATE_LIMIT, VERIFY_WINDOW_SECONDS)

app = FastAPI(title="Luna Key Backend", version="1.0.0")

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["POST", "GET"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/")
def root() -> dict:
    return {"service": "luna-key-backend", "status": "ok"}


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "time_utc": utc_now().isoformat()}


@app.post("/api/v1/auth/verify-key", response_model=VerifyKeyResponse)
def verify_key(payload: VerifyKeyRequest, request: Request, db: Session = Depends(get_db)) -> VerifyKeyResponse:
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = verify_rate_limiter.check(f"verify:{client_ip}")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry in {retry_after}s.",
        )

    digest = key_hash(payload.key)
    record = db.scalar(select(LicenseKey).where(LicenseKey.key_hash == digest))
    if record is None:
        return VerifyKeyResponse(valid=False, message="invalid_or_expired")

    now = utc_now()

    if not record.is_active or record.revoked_at is not None:
        return VerifyKeyResponse(valid=False, message="invalid_or_expired")

    if record.duration_days and record.expires_at is None:
        # Expiry starts on first successful use.
        record.first_used_at = record.first_used_at or now
        record.expires_at = record.first_used_at + timedelta(days=record.duration_days)

    if record.expires_at is not None and now >= record.expires_at:
        record.is_active = False
        db.commit()
        return VerifyKeyResponse(valid=False, message="invalid_or_expired")

    if record.bind_to_device:
        if not payload.device_id:
            return VerifyKeyResponse(valid=False, message="device_required")

        incoming_device_hash = device_hash(payload.device_id)
        if record.bound_device_hash is None:
            record.bound_device_hash = incoming_device_hash
        elif not hmac.compare_digest(record.bound_device_hash, incoming_device_hash):
            return VerifyKeyResponse(valid=False, message="device_mismatch")

    if record.first_used_at is None:
        record.first_used_at = now
    record.last_used_at = now

    db.commit()
    return VerifyKeyResponse(
        valid=True,
        plan=PlanType(record.plan),
        expires_at=record.expires_at,
        message="ok",
    )


@app.post("/api/v1/admin/keys/generate", response_model=GenerateKeysResponse, dependencies=[Depends(require_admin)])
def generate_keys(payload: GenerateKeysRequest, db: Session = Depends(get_db)) -> GenerateKeysResponse:
    keys_out: list[GeneratedKeyItem] = []
    duration_days = plan_duration_days(payload.plan)

    for _ in range(payload.quantity):
        created = False
        for _attempt in range(12):
            raw = random_key()
            record = LicenseKey(
                key_hash=key_hash(raw),
                key_hint=raw[-8:],
                plan=payload.plan.value,
                duration_days=duration_days,
                bind_to_device=payload.bind_to_device,
                note=payload.note,
            )
            db.add(record)
            try:
                db.commit()
                db.refresh(record)
                keys_out.append(
                    GeneratedKeyItem(
                        id=record.id,
                        key=raw,
                        plan=payload.plan,
                        duration_days=duration_days,
                        bind_to_device=record.bind_to_device,
                        created_at=record.created_at,
                    )
                )
                created = True
                break
            except IntegrityError:
                db.rollback()

        if not created:
            raise HTTPException(status_code=500, detail="Unable to generate unique key. Try again.")

    return GenerateKeysResponse(keys=keys_out)


@app.post("/api/v1/admin/keys/revoke", dependencies=[Depends(require_admin)])
def revoke_key(payload: RevokeKeyRequest, db: Session = Depends(get_db)) -> dict:
    if not payload.key and not payload.key_id:
        raise HTTPException(status_code=400, detail="Provide key or key_id.")

    record: Optional[LicenseKey] = None
    if payload.key:
        digest = key_hash(payload.key)
        record = db.scalar(select(LicenseKey).where(LicenseKey.key_hash == digest))
    elif payload.key_id:
        record = db.scalar(select(LicenseKey).where(LicenseKey.id == payload.key_id.strip()))

    if record is None:
        raise HTTPException(status_code=404, detail="Key not found.")

    record.is_active = False
    record.revoked_at = utc_now()
    db.commit()
    return {"status": "revoked", "key_id": record.id}


@app.get("/api/v1/admin/keys", response_model=list[KeyMetaResponse], dependencies=[Depends(require_admin)])
def list_keys(limit: int = 50, db: Session = Depends(get_db)) -> list[KeyMetaResponse]:
    safe_limit = max(1, min(500, limit))
    rows = db.scalars(select(LicenseKey).order_by(LicenseKey.created_at.desc()).limit(safe_limit)).all()
    return [
        KeyMetaResponse(
            id=row.id,
            key_hint=row.key_hint,
            plan=PlanType(row.plan),
            duration_days=row.duration_days,
            created_at=row.created_at,
            first_used_at=row.first_used_at,
            last_used_at=row.last_used_at,
            expires_at=row.expires_at,
            is_active=row.is_active,
            revoked_at=row.revoked_at,
            bind_to_device=row.bind_to_device,
            note=row.note,
        )
        for row in rows
    ]

