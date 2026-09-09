from datetime import UTC, datetime
from typing import Generator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, Numeric, ForeignKey, JSON, UniqueConstraint, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

class Settings(BaseSettings):
    app_name: str = 'WinGate API'
    environment: str = 'development'
    debug: bool = False
    database_url: str = 'sqlite:///./user_state.db'
    jwt_secret_key: str = 'change-me'
    jwt_algorithm: str = 'HS256'
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    min_password_length: int = 8
    page_stale_seconds: int = 120
    game_heartbeat_grace_seconds: int = 90
    game_session_ttl_seconds: int = 3600
    action_token_ttl_seconds: int = 60
    launch_ticket_ttl_seconds: int = 120
    login_rate_limit_per_minute: int = 10
    idempotency_ttl_seconds: int = 86400
    cors_origins: str = 'http://localhost:3000'
    provider_api_url: str = 'https://api.shreewinapi.com'
    provider_origin: str = 'https://shreewin39.com'
    game_base_url: str = 'https://h5.ar-lottery01.com'
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    @property
    def cors_origin_list(self): return [x.strip() for x in self.cors_origins.split(',') if x.strip()]

settings = Settings()
if settings.environment == "production" and (len(settings.jwt_secret_key) < 32 or "change-me" in settings.jwt_secret_key or "replace-this" in settings.jwt_secret_key):
    raise RuntimeError("JWT_SECRET_KEY must be set to 32+ random chars in production")
db_url = settings.database_url
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif db_url.startswith('postgresql://') and not db_url.startswith('postgresql+'):
    db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)

connect_args = {'check_same_thread': False} if db_url.startswith('sqlite') else {}
engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

class Base(DeclarativeBase): pass

def utcnow(): return datetime.now(UTC).replace(tzinfo=None)

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    identifier: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    invite_code: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    external_uid: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default='active')
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), index=True)
    refresh_family_id: Mapped[str] = mapped_column(String(64), index=True, default='')
    refresh_token_version: Mapped[int] = mapped_column(Integer, default=1)
    refresh_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class RefreshTokenRecord(Base):
    __tablename__ = 'refresh_token_records'
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String(64), index=True)
    auth_session_id: Mapped[str] = mapped_column(ForeignKey('auth_sessions.id'), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class Balance(Base):
    __tablename__ = 'balances'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    cash_available: Mapped[float] = mapped_column(Numeric(18, 2), default=0)
    bonus_available: Mapped[float] = mapped_column(Numeric(18, 2), default=0)
    locked_amount: Mapped[float] = mapped_column(Numeric(18, 2), default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class PageState(Base):
    __tablename__ = 'page_states'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    tab_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    route: Mapped[str] = mapped_column(String(500))
    page_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class GameSession(Base):
    __tablename__ = 'game_sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    auth_session_id: Mapped[str] = mapped_column(ForeignKey('auth_sessions.id'), index=True)
    game_id: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default='PENDING', index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    exit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class GameLaunchTicket(Base):
    __tablename__ = 'game_launch_tickets'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ticket_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    auth_session_id: Mapped[str] = mapped_column(ForeignKey('auth_sessions.id'), index=True)
    game_session_id: Mapped[str] = mapped_column(ForeignKey('game_sessions.id'), index=True)
    game_id: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id: Mapped[int] = mapped_column(primary_key=True)
    event: Mapped[str] = mapped_column(String(80), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ActionNonce(Base):
    __tablename__ = 'action_nonces'
    nonce: Mapped[str] = mapped_column(String(100), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint('nonce', name='uq_action_nonce'),)

class ActionAuditRecord(Base):
    __tablename__ = 'action_audit_records'
    id: Mapped[int] = mapped_column(primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    auth_session_id: Mapped[str] = mapped_column(String(64), index=True)
    game_session_id: Mapped[str] = mapped_column(String(64), index=True)
    operation: Mapped[str] = mapped_column(String(80), index=True)
    request_id: Mapped[str] = mapped_column(String(100), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    amount: Mapped[float] = mapped_column(Numeric(18, 2), default=0)
    balance_before: Mapped[float | None] = mapped_column(Numeric(18, 2), nullable=True)
    balance_after: Mapped[float | None] = mapped_column(Numeric(18, 2), nullable=True)
    balance_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default='SUCCESS', index=True)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class IdempotencyRecord(Base):
    __tablename__ = 'idempotency_records'
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    operation: Mapped[str] = mapped_column(String(80), index=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    status_code: Mapped[int] = mapped_column(Integer)
    response_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class AppConfigRecord(Base):
    __tablename__ = 'app_configs'
    channel: Mapped[str] = mapped_column(String(64), primary_key=True)
    app_active: Mapped[bool] = mapped_column(Boolean, default=True)
    min_unlock_balance: Mapped[float] = mapped_column(Numeric(18, 2), default=50.0)
    unlock_without_deposit: Mapped[bool] = mapped_column(Boolean, default=False)
    whitelisted_users: Mapped[dict | list | None] = mapped_column(JSON, default=list)
    blacklisted_users: Mapped[dict | list | None] = mapped_column(JSON, default=list)
    broadcast_notice: Mapped[str] = mapped_column(String(500), default="Welcome • Signals are entertainment only • 18+ play responsibly")
    broadcast_priority: Mapped[str] = mapped_column(String(30), default="important")
    deposit_url: Mapped[str] = mapped_column(String(500), default="https://www.shreewin.ai/#/wallet/Recharge")
    register_url: Mapped[str] = mapped_column(String(500), default="https://www.shreewin6.com/#/register?invitationCode=78763141420")
    bubble_icon_url: Mapped[str] = mapped_column(String(500), default="https://i.ibb.co/fGpr57nL/20260904-132124.webp")
    branding_panel_name: Mapped[str] = mapped_column(String(64), default="NEXY")
    branding_bubble_label: Mapped[str] = mapped_column(String(64), default="NEXY")
    branding_theme_color: Mapped[str] = mapped_column(String(32), default="#8C25E3")
    win_feed_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    strict_reg_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[str] = mapped_column(String(32), default="2.0.0")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class DeviceTelemetryRecord(Base):
    __tablename__ = 'device_telemetry'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(100), index=True)
    user_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    balance: Mapped[float] = mapped_column(Numeric(18, 2), default=0.0)
    peak_balance: Mapped[float] = mapped_column(Numeric(18, 2), default=0.0)
    game: Mapped[str] = mapped_column(String(100), default="WinGo 1-Min")
    state: Mapped[str] = mapped_column(String(64), default="STATE_LIVE_WINGO")
    device_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_brand: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_os: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_emulator: Mapped[bool] = mapped_column(Boolean, default=False)
    is_rooted: Mapped[bool] = mapped_column(Boolean, default=False)
    risk: Mapped[str] = mapped_column(String(50), default="")
    channel: Mapped[str] = mapped_column(String(64), default="default", index=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    logins: Mapped[int] = mapped_column(Integer, default=1)
    total_pings: Mapped[int] = mapped_column(Integer, default=1)

class AppScriptRecord(Base):
    __tablename__ = 'app_scripts'
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    sha256: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class AppReleaseRecord(Base):
    __tablename__ = 'app_releases'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    flavor: Mapped[str] = mapped_column(String(32), index=True)
    version_code: Mapped[int] = mapped_column(Integer, index=True)
    version_name: Mapped[str] = mapped_column(String(32))
    force_update: Mapped[bool] = mapped_column(Boolean, default=False)
    download_url: Mapped[str] = mapped_column(String(500))
    changelog: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppRegisteredUser(Base):
    __tablename__ = 'app_registered_users'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    # mirrors worker register payload verbatim; never read back for auth (plaintext upstream)
    password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    invite_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    channel: Mapped[str] = mapped_column(String(64), default='default')
    device_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def init_db():
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        try:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN invite_code VARCHAR(64)")
        except Exception:
            pass
        try:
            conn.exec_driver_sql("ALTER TABLE app_configs ADD COLUMN unlock_without_deposit BOOLEAN DEFAULT FALSE")
        except Exception:
            pass
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try: yield db
    finally: db.close()

