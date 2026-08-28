from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from contextlib import asynccontextmanager
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from threading import Lock
from typing import Generator
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, String, create_engine, delete, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, joinedload, mapped_column, relationship, sessionmaker

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # The API still works when location support is intentionally omitted.
    geoip2 = None


load_dotenv()


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
ALLOWED_AVATARS = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".webp": "WEBP",
}
MAX_AVATAR_BYTES = 5 * 1024 * 1024
MAX_AVATAR_PIXELS = 20_000_000
SESSION_LIFETIME = timedelta(days=7)
REMEMBER_COOKIE_SECONDS = int(SESSION_LIFETIME.total_seconds())
PASSWORD_HASHER = PasswordHasher()


def env_flag(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/heart_non_pro.db")
    avatar_directory: Path = Path(os.getenv("AVATAR_DIRECTORY", "./data/avatars"))
    cors_origins: tuple[str, ...] = tuple(
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()
    )
    cookie_secure: bool = env_flag("COOKIE_SECURE", True)
    cookie_samesite: str = os.getenv("COOKIE_SAMESITE", "none").strip().lower()
    trusted_proxy_ips: frozenset[str] = frozenset(
        address.strip() for address in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if address.strip()
    )
    geolite_city_database: Path = Path(os.getenv("GEOLITE_CITY_DATABASE", "./data/GeoLite2-City.mmdb"))


settings = Settings()
if settings.cookie_samesite not in {"lax", "strict", "none"}:
    raise RuntimeError("COOKIE_SAMESITE must be lax, strict, or none.")
if settings.cookie_samesite == "none" and not settings.cookie_secure:
    raise RuntimeError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true.")

settings.avatar_directory.mkdir(parents=True, exist_ok=True)
if settings.database_url.startswith("sqlite:///"):
    Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

engine_options: dict[str, object] = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(settings.database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection: object, connection_record: object) -> None:
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    username_normalized: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    avatar_filename: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    sessions: Mapped[list[AccountSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class AccountSession(Base):
    __tablename__ = "account_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    remember_me: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    device_name: Mapped[str] = mapped_column(String(80), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    location: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    user: Mapped[User] = relationship(back_populates="sessions")


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    remember_me: bool = False


class UsernamePayload(BaseModel):
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return normalize_username(value)


class PasswordPayload(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)


@dataclass
class AuthenticatedSession:
    session: AccountSession
    user: User
    raw_token: str


def utc_now() -> datetime:
    # SQLite stores naive values; this project consistently treats them as UTC.
    return datetime.utcnow()


def normalize_username(value: str) -> str:
    username = value.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Имя пользователя: 3-32 символа, латинские буквы, цифры, . _ или -.")
    return username


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def iso_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds") + "Z"


def serialize_user(user: User) -> dict[str, str | None]:
    return {
        "username": user.username,
        "avatarUrl": f"/media/avatars/{user.avatar_filename}" if user.avatar_filename else None,
    }


def get_db() -> Generator[Session, None, None]:
    database = SessionLocal()
    try:
        yield database
    finally:
        database.close()


def cleanup_expired_sessions(database: Session) -> None:
    database.execute(delete(AccountSession).where(AccountSession.expires_at <= utc_now()))


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie("heart_session", path="/", secure=settings.cookie_secure, samesite=settings.cookie_samesite)


def set_session_cookie(response: Response, raw_token: str, remember_me: bool) -> None:
    options: dict[str, object] = {
        "key": "heart_session",
        "value": raw_token,
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": settings.cookie_samesite,
        "path": "/",
    }
    if remember_me:
        options["max_age"] = REMEMBER_COOKIE_SECONDS
    response.set_cookie(**options)


def client_ip(request: Request) -> str:
    remote_ip = request.client.host if request.client else ""
    if remote_ip in settings.trusted_proxy_ips:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return remote_ip


def identify_device(user_agent: str) -> tuple[str, str]:
    agent = user_agent.lower()
    if "iphone" in agent:
        return "iPhone", "iOS"
    if "ipad" in agent:
        return "iPad", "iOS"
    if "android" in agent:
        return ("Android Phone" if "mobile" in agent else "Android device"), "Android"
    if "windows" in agent:
        return "Windows PC", "Windows"
    if "mac os" in agent or "macintosh" in agent:
        return "Mac", "macOS"
    if "linux" in agent:
        return "Linux device", "Linux"
    return "Unknown device", "Unknown"


def locate_ip(ip: str, reader: object | None) -> str | None:
    if not reader:
        return None
    try:
        if not ip or ipaddress.ip_address(ip).is_private:
            return None
        response = reader.city(ip)  # type: ignore[union-attr]
        city = response.city.name
        country = response.country.name
        return ", ".join(part for part in (city, country) if part) or None
    except Exception:
        # Geolocation is supplementary: a missing or stale GeoLite record must never block login.
        return None


def get_authentication(request: Request, database: Session = Depends(get_db)) -> AuthenticatedSession:
    raw_token = request.cookies.get("heart_session")
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется авторизация.")

    session = database.scalar(
        select(AccountSession)
        .options(joinedload(AccountSession.user))
        .where(AccountSession.token_hash == token_hash(raw_token))
    )
    if not session or session.expires_at <= utc_now():
        if session:
            database.delete(session)
            database.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия истекла.")

    now = utc_now()
    session.last_seen_at = now
    session.expires_at = now + SESSION_LIFETIME
    database.commit()
    return AuthenticatedSession(session=session, user=session.user, raw_token=raw_token)


def require_csrf(request: Request, authenticated: AuthenticatedSession) -> None:
    submitted_token = request.headers.get("x-csrf-token", "")
    if not submitted_token or not hmac.compare_digest(token_hash(submitted_token), authenticated.session.csrf_token_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недействительный защитный токен.")


def session_payload(session: AccountSession, current_session_id: str) -> dict[str, str | bool | None]:
    return {
        "id": session.id,
        "deviceName": session.device_name,
        "platform": session.platform,
        "location": session.location,
        "createdAt": iso_timestamp(session.created_at),
        "lastSeenAt": iso_timestamp(session.last_seen_at),
        "isCurrent": session.id == current_session_id,
    }


class LoginRateLimiter:
    def __init__(self) -> None:
        self._attempts: dict[str, list[datetime]] = {}
        self._lock = Lock()

    def allow(self, ip: str) -> bool:
        now = utc_now()
        cutoff = now - timedelta(minutes=15)
        with self._lock:
            attempts = [attempt for attempt in self._attempts.get(ip, []) if attempt > cutoff]
            if len(attempts) >= 8:
                self._attempts[ip] = attempts
                return False
            attempts.append(now)
            self._attempts[ip] = attempts
            return True

    def clear(self, ip: str) -> None:
        with self._lock:
            self._attempts.pop(ip, None)


login_limiter = LoginRateLimiter()


async def purge_expired_sessions_forever() -> None:
    while True:
        with SessionLocal() as database:
            cleanup_expired_sessions(database)
            database.commit()
        await asyncio.sleep(60 * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as database:
        cleanup_expired_sessions(database)
        database.commit()
    geo_reader = None
    if settings.geolite_city_database.is_file() and geoip2 is not None:
        geo_reader = geoip2.database.Reader(str(settings.geolite_city_database))
    app.state.geo_reader = geo_reader
    cleanup_task = asyncio.create_task(purge_expired_sessions_forever())
    try:
        yield
    finally:
        cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup_task
        if geo_reader:
            geo_reader.close()


app = FastAPI(title="Heart Non Pro Account API", docs_url=None, redoc_url=None, lifespan=lifespan)
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )
app.mount("/media/avatars", StaticFiles(directory=settings.avatar_directory), name="avatars")


@app.get("/api/health")
def healthcheck() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request, response: Response, database: Session = Depends(get_db)) -> dict[str, object]:
    ip = client_ip(request)
    if not login_limiter.allow(ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Слишком много попыток. Попробуйте позже.")

    try:
        normalized_username = normalize_username(payload.username).casefold()
    except ValueError:
        normalized_username = ""
    user = database.scalar(select(User).where(User.username_normalized == normalized_username)) if normalized_username else None

    try:
        password_is_valid = bool(user and PASSWORD_HASHER.verify(user.password_hash, payload.password))
    except (VerifyMismatchError, InvalidHashError):
        password_is_valid = False

    if not password_is_valid or not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверное имя пользователя или пароль.")

    login_limiter.clear(ip)
    cleanup_expired_sessions(database)
    now = utc_now()
    raw_session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    device_name, platform = identify_device(request.headers.get("user-agent", ""))
    account_session = AccountSession(
        user_id=user.id,
        token_hash=token_hash(raw_session_token),
        csrf_token_hash=token_hash(csrf_token),
        remember_me=payload.remember_me,
        device_name=device_name,
        platform=platform,
        location=locate_ip(ip, getattr(request.app.state, "geo_reader", None)),
        created_at=now,
        last_seen_at=now,
        expires_at=now + SESSION_LIFETIME,
    )
    database.add(account_session)
    database.commit()
    set_session_cookie(response, raw_session_token, payload.remember_me)
    return {"user": serialize_user(user), "csrfToken": csrf_token}


@app.get("/api/auth/me")
def current_user(response: Response, authenticated: AuthenticatedSession = Depends(get_authentication)) -> dict[str, object]:
    # The frontend keeps this token in memory only and sends it on state-changing requests.
    csrf_token = secrets.token_urlsafe(32)
    authenticated.session.csrf_token_hash = token_hash(csrf_token)
    database = Session.object_session(authenticated.session)
    if database:
        database.commit()
    set_session_cookie(response, authenticated.raw_token, authenticated.session.remember_me)
    return {"user": serialize_user(authenticated.user), "csrfToken": csrf_token}


@app.post("/api/auth/heartbeat")
def heartbeat(response: Response, request: Request, authenticated: AuthenticatedSession = Depends(get_authentication)) -> dict[str, bool]:
    require_csrf(request, authenticated)
    set_session_cookie(response, authenticated.raw_token, authenticated.session.remember_me)
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(response: Response, request: Request, authenticated: AuthenticatedSession = Depends(get_authentication)) -> dict[str, bool]:
    require_csrf(request, authenticated)
    database = Session.object_session(authenticated.session)
    if database:
        database.delete(authenticated.session)
        database.commit()
    clear_session_cookie(response)
    return {"ok": True}


@app.patch("/api/account/username")
def change_username(
    payload: UsernamePayload,
    request: Request,
    authenticated: AuthenticatedSession = Depends(get_authentication),
) -> dict[str, object]:
    require_csrf(request, authenticated)
    normalized_username = payload.username.casefold()
    database = Session.object_session(authenticated.session)
    assert database is not None
    other_user = database.scalar(select(User.id).where(User.username_normalized == normalized_username))
    if other_user and other_user != authenticated.user.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Это имя пользователя уже занято.")
    authenticated.user.username = payload.username
    authenticated.user.username_normalized = normalized_username
    authenticated.user.updated_at = utc_now()
    database.commit()
    return {"user": serialize_user(authenticated.user)}


@app.patch("/api/account/password")
def change_password(
    payload: PasswordPayload,
    request: Request,
    authenticated: AuthenticatedSession = Depends(get_authentication),
) -> dict[str, bool]:
    require_csrf(request, authenticated)
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Новые пароли не совпадают.")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Новый пароль должен отличаться от текущего.")
    try:
        current_password_is_valid = PASSWORD_HASHER.verify(authenticated.user.password_hash, payload.current_password)
    except (VerifyMismatchError, InvalidHashError):
        current_password_is_valid = False
    if not current_password_is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Текущий пароль указан неверно.")

    database = Session.object_session(authenticated.session)
    assert database is not None
    authenticated.user.password_hash = PASSWORD_HASHER.hash(payload.new_password)
    authenticated.user.updated_at = utc_now()
    # Any older device must authenticate again after a password change.
    database.execute(
        delete(AccountSession).where(
            AccountSession.user_id == authenticated.user.id,
            AccountSession.id != authenticated.session.id,
        )
    )
    database.commit()
    return {"ok": True}


@app.post("/api/account/avatar")
async def upload_avatar(
    request: Request,
    avatar: UploadFile = File(...),
    authenticated: AuthenticatedSession = Depends(get_authentication),
) -> dict[str, object]:
    require_csrf(request, authenticated)
    suffix = Path(avatar.filename or "").suffix.lower()
    if suffix not in ALLOWED_AVATARS or avatar.content_type not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Поддерживаются только JPG, PNG и WebP до 5 МБ.")

    content = await avatar.read(MAX_AVATAR_BYTES + 1)
    await avatar.close()
    if len(content) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Размер файла не должен превышать 5 МБ.")

    try:
        with Image.open(BytesIO(content)) as validation_image:
            validation_format = validation_image.format
            if validation_format != ALLOWED_AVATARS[suffix]:
                raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Формат файла не соответствует его расширению.")
            if validation_image.width * validation_image.height > MAX_AVATAR_PIXELS:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Изображение слишком большое.")
            validation_image.verify()
        with Image.open(BytesIO(content)) as source_image:
            source_image.load()
            image = ImageOps.fit(source_image.convert("RGB"), (512, 512), method=Image.Resampling.LANCZOS)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Не удалось обработать это изображение.")

    filename = f"{uuid4().hex}.webp"
    destination = settings.avatar_directory / filename
    temporary_destination = settings.avatar_directory / f"{filename}.uploading"
    image.save(temporary_destination, format="WEBP", quality=88, method=6)
    os.replace(temporary_destination, destination)

    database = Session.object_session(authenticated.session)
    assert database is not None
    previous_filename = authenticated.user.avatar_filename
    try:
        authenticated.user.avatar_filename = filename
        authenticated.user.updated_at = utc_now()
        database.commit()
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if previous_filename:
        (settings.avatar_directory / previous_filename).unlink(missing_ok=True)
    return {"user": serialize_user(authenticated.user)}


@app.get("/api/account/sessions")
def list_sessions(authenticated: AuthenticatedSession = Depends(get_authentication)) -> dict[str, list[dict[str, str | bool | None]]]:
    database = Session.object_session(authenticated.session)
    assert database is not None
    cleanup_expired_sessions(database)
    database.commit()
    sessions = database.scalars(
        select(AccountSession)
        .where(AccountSession.user_id == authenticated.user.id)
        .order_by(AccountSession.last_seen_at.desc())
    ).all()
    return {"sessions": [session_payload(item, authenticated.session.id) for item in sessions]}
