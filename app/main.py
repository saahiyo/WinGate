import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from decimal import Decimal
import secrets

from fastapi import FastAPI, Depends, HTTPException, Header, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .core import (
    settings,
    init_db,
    get_db,
    utcnow,
    User,
    AuthSession,
    RefreshTokenRecord,
    Balance,
    PageState,
    GameSession,
    GameLaunchTicket,
    AuditEvent,
    ActionNonce,
    ActionAuditRecord,
    IdempotencyRecord,
    AppConfigRecord,
    DeviceTelemetryRecord,
)
from .security import (
    hash_password,
    verify_password,
    hash_secret,
    create_access_token,
    require_context,
    new_id,
    api_error,
)
from .provider import (
    call_provider_api,
    parse_wingo_type_id,
    enrich_wingo_result,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title=settings.app_name,
    version='1.1.0',
    description='Server-authoritative identity, balance, page, game-session, and action authorization API.',
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=['GET', 'POST'],
    allow_headers=['Authorization', 'Content-Type', 'X-Device-Id', 'Idempotency-Key'],
)

class RegisterIn(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)
    invite_code: str | None = Field(default=None, max_length=64)

class LoginIn(BaseModel):
    identifier: str
    password: str
    device_id: str | None = Field(default=None, max_length=255)

class RefreshIn(BaseModel):
    refresh_token: str

class PageIn(BaseModel):
    route: str = Field(min_length=1, max_length=500)
    page_name: str | None = Field(default=None, max_length=100)
    tab_id: str | None = Field(default=None, max_length=100)

class LaunchIn(BaseModel):
    game_id: str = Field(min_length=1, max_length=255)
    vendor: str | None = Field(default=None, max_length=100)
    game_base_url: str | None = Field(default=None, max_length=500)

class ConsumeTicketIn(BaseModel):
    launch_ticket: str = Field(min_length=1)
    game_session_id: str = Field(min_length=1)

class ActionIn(BaseModel):
    game_session_id: str
    required_balance: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    client_request_id: str = Field(min_length=8, max_length=100)

class ActionExecuteIn(BaseModel):
    client_request_id: str = Field(min_length=8, max_length=100)
    amount: Decimal = Field(ge=0, max_digits=18, decimal_places=2, default=Decimal('0.00'))
    metadata: dict | None = None

class SettleIn(BaseModel):
    client_request_id: str = Field(min_length=8, max_length=100)
    payout_amount: Decimal = Field(ge=0, max_digits=18, decimal_places=2, default=Decimal('0.00'))
    metadata: dict | None = None

@app.get('/healthz')
def healthz():
    return {
        'status': 'ok',
        'environment': settings.environment,
        'provider_api_url': settings.provider_api_url,
        'game_base_url': settings.game_base_url,
    }

@app.post('/auth/register', status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if len(body.password) < settings.min_password_length:
        raise api_error(422, 'WEAK_PASSWORD', f'Password must contain at least {settings.min_password_length} characters')
    identifier = body.identifier.strip().lower()
    if db.scalar(select(User).where(User.identifier == identifier)):
        raise api_error(409, 'USER_EXISTS', 'An account already exists')
    invite_code = body.invite_code.strip() if body.invite_code and body.invite_code.strip() else None
    user = User(identifier=identifier, password_hash=hash_password(body.password), invite_code=invite_code)
    db.add(user)
    db.flush()
    db.add(Balance(user_id=user.id))
    db.add(AuditEvent(event='USER_REGISTERED', user_id=user.id, metadata_json={'source': 'api', 'invite_code': invite_code}))
    db.commit()
    return {
        'user_id': user.id,
        'registered': True,
        'registered_at': user.registered_at,
        'invite_code': user.invite_code,
    }

@app.post('/auth/login')
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.identifier == body.identifier.strip().lower()))
    if not user or not verify_password(body.password, user.password_hash):
        raise api_error(401, 'AUTH_REQUIRED', 'Invalid credentials')
    if user.status != 'active':
        raise api_error(403, 'ACCOUNT_DISABLED', 'Account is disabled or inactive')

    sid = new_id()
    family_id = new_id()
    refresh = secrets.token_urlsafe(48)
    refresh_hash_val = hash_secret(refresh)
    now = utcnow()
    sess_expiry = now + timedelta(days=settings.refresh_token_days)

    sess = AuthSession(
        id=sid,
        user_id=user.id,
        refresh_hash=refresh_hash_val,
        refresh_family_id=family_id,
        refresh_token_version=1,
        device_id=body.device_id,
        expires_at=sess_expiry,
    )
    db.add(sess)

    token_rec = RefreshTokenRecord(
        token_hash=refresh_hash_val,
        family_id=family_id,
        auth_session_id=sid,
        user_id=user.id,
        version=1,
        is_used=False,
        expires_at=sess_expiry,
    )
    db.add(token_rec)

    db.add(AuditEvent(event='USER_LOGGED_IN', user_id=user.id, session_id=sid))
    db.commit()

    return {
        'access_token': create_access_token(user.id, sid),
        'token_type': 'bearer',
        'refresh_token': refresh,
        'session_id': sid,
        'user_id': user.id,
        'external_uid': user.external_uid,
        'shreewin_uid': user.external_uid,
        'expires_at': sess.expires_at,
    }

@app.post('/auth/refresh')
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    req_hash = hash_secret(body.refresh_token)
    token_rec = db.scalar(select(RefreshTokenRecord).where(RefreshTokenRecord.token_hash == req_hash))
    now = utcnow()

    if not token_rec:
        # Fallback check on AuthSession
        sess = db.scalar(select(AuthSession).where(AuthSession.refresh_hash == req_hash))
        if not sess or sess.revoked_at or sess.expires_at <= now:
            raise api_error(401, 'AUTH_REVOKED', 'Refresh token is invalid or expired')
        new_refresh = secrets.token_urlsafe(48)
        new_hash = hash_secret(new_refresh)
        sess.refresh_hash = new_hash
        sess.refresh_rotated_at = now
        sess.refresh_token_version += 1
        db.add(
            RefreshTokenRecord(
                token_hash=new_hash,
                family_id=sess.refresh_family_id or sess.id,
                auth_session_id=sess.id,
                user_id=sess.user_id,
                version=sess.refresh_token_version,
                is_used=False,
                expires_at=sess.expires_at,
            )
        )
        db.commit()
        return {
            'access_token': create_access_token(sess.user_id, sess.id),
            'token_type': 'bearer',
            'refresh_token': new_refresh,
        }

    # Reuse detection
    if token_rec.is_used:
        sess = db.get(AuthSession, token_rec.auth_session_id)
        if sess:
            sess.revoked_at = now
        # Cascade revoke game sessions
        db.query(GameSession).filter(
            GameSession.auth_session_id == token_rec.auth_session_id,
            GameSession.state.in_(['PENDING', 'ACTIVE']),
        ).update({'state': 'REVOKED', 'exit_at': now})
        db.add(
            AuditEvent(
                event='REFRESH_REUSE_DETECTED',
                user_id=token_rec.user_id,
                session_id=token_rec.auth_session_id,
                metadata_json={'family_id': token_rec.family_id, 'version': token_rec.version},
            )
        )
        db.commit()
        raise api_error(401, 'AUTH_REVOKED', 'Refresh token reuse detected; all associated sessions have been revoked')

    if token_rec.expires_at <= now:
        raise api_error(401, 'AUTH_EXPIRED', 'Refresh token has expired')

    sess = db.get(AuthSession, token_rec.auth_session_id)
    if not sess or sess.revoked_at or sess.expires_at <= now:
        raise api_error(401, 'AUTH_REVOKED', 'Session is invalid or expired')

    # Consume current token
    token_rec.is_used = True
    token_rec.used_at = now

    # Issue rotated token
    new_refresh = secrets.token_urlsafe(48)
    new_hash = hash_secret(new_refresh)
    new_version = token_rec.version + 1

    sess.refresh_hash = new_hash
    sess.refresh_token_version = new_version
    sess.refresh_rotated_at = now

    new_rec = RefreshTokenRecord(
        token_hash=new_hash,
        family_id=token_rec.family_id,
        auth_session_id=sess.id,
        user_id=sess.user_id,
        version=new_version,
        is_used=False,
        expires_at=sess.expires_at,
    )
    db.add(new_rec)
    db.add(AuditEvent(event='REFRESH_TOKEN_ROTATED', user_id=sess.user_id, session_id=sess.id, metadata_json={'version': new_version}))
    db.commit()

    return {
        'access_token': create_access_token(sess.user_id, sess.id),
        'token_type': 'bearer',
        'refresh_token': new_refresh,
    }

@app.post('/auth/logout')
def logout(ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    sess.revoked_at = now
    db.query(RefreshTokenRecord).filter(RefreshTokenRecord.auth_session_id == sess.id).update({'is_used': True, 'used_at': now})
    db.query(GameSession).filter(
        GameSession.auth_session_id == sess.id,
        GameSession.state.in_(['PENDING', 'ACTIVE']),
    ).update({'state': 'REVOKED', 'exit_at': now})
    db.query(GameLaunchTicket).filter(
        GameLaunchTicket.auth_session_id == sess.id,
        GameLaunchTicket.consumed_at.is_(None),
    ).update({'consumed_at': now})
    db.add(AuditEvent(event='USER_LOGGED_OUT', user_id=user.id, session_id=sess.id))
    db.commit()
    return {'logged_out': True}

@app.get('/me')
def me(ctx=Depends(require_context)):
    user, sess = ctx
    return {
        'authenticated': True,
        'user_id': user.id,
        'external_uid': user.external_uid,
        'shreewin_uid': user.external_uid,
        'session_id': sess.id,
        'invite_code': user.invite_code,
        'registered_at': user.registered_at,
        'session_expires_at': sess.expires_at,
        'last_seen_at': sess.last_seen_at,
    }

@app.get('/wallet/available-balance')
def balance(ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, _ = ctx
    b = db.get(Balance, user.id)
    available = Decimal(str(b.cash_available)) - Decimal(str(b.locked_amount))
    return {
        'user_id': user.id,
        'cash_available': float(b.cash_available),
        'bonus_available': float(b.bonus_available),
        'locked_amount': float(b.locked_amount),
        'available_for_game': float(max(available, Decimal('0.00'))),
        'balance_version': b.version,
        'as_of': b.updated_at,
    }

@app.post('/telemetry/page-view')
def page_view(body: PageIn, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    p = db.scalar(
        select(PageState).where(
            PageState.user_id == user.id,
            PageState.session_id == sess.id,
            PageState.tab_id == body.tab_id,
        )
    )
    if not p:
        p = PageState(
            user_id=user.id,
            session_id=sess.id,
            route=body.route,
            page_name=body.page_name,
            tab_id=body.tab_id,
        )
        db.add(p)
    else:
        p.route = body.route
        p.page_name = body.page_name
        p.last_seen_at = utcnow()
    db.commit()
    return {'recorded': True, 'last_seen_at': p.last_seen_at}

@app.post('/games/launch')
def launch(body: LaunchIn, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    gid = new_id()
    raw_ticket = secrets.token_urlsafe(32)
    ticket_hash = hash_secret(raw_ticket)
    ticket_expires_at = now + timedelta(seconds=settings.launch_ticket_ttl_seconds)
    session_expires_at = now + timedelta(seconds=settings.game_session_ttl_seconds)

    gs = GameSession(
        id=gid,
        user_id=user.id,
        auth_session_id=sess.id,
        game_id=body.game_id,
        vendor=body.vendor,
        state='PENDING',
        created_at=now,
        expires_at=session_expires_at,
        last_heartbeat_at=now,
    )
    db.add(gs)

    ticket = GameLaunchTicket(
        id=new_id(),
        ticket_hash=ticket_hash,
        user_id=user.id,
        auth_session_id=sess.id,
        game_session_id=gid,
        game_id=body.game_id,
        vendor=body.vendor,
        created_at=now,
        expires_at=ticket_expires_at,
        consumed_at=None,
    )
    db.add(ticket)

    db.add(
        AuditEvent(
            event='GAME_SESSION_STARTED',
            user_id=user.id,
            session_id=sess.id,
            metadata_json={'game_id': body.game_id, 'vendor': body.vendor, 'game_session_id': gid},
        )
    )
    db.commit()

    base_url = (body.game_base_url or settings.game_base_url).rstrip('/')
    launch_url = f'{base_url}/?game_id={body.game_id}&session_id={gid}&ticket={raw_ticket}'

    return {
        'game_session_id': gid,
        'state': gs.state,
        'expires_at': gs.expires_at,
        'launch_ticket': raw_ticket,
        'ticket_expires_at': ticket.expires_at,
        'launch_url': launch_url,
    }

@app.post('/games/tickets/consume')
def consume_ticket(body: ConsumeTicketIn, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    thash = hash_secret(body.launch_ticket)
    ticket = db.scalar(select(GameLaunchTicket).where(GameLaunchTicket.ticket_hash == thash))

    if not ticket or ticket.user_id != user.id or ticket.auth_session_id != sess.id or ticket.game_session_id != body.game_session_id:
        raise api_error(404, 'LAUNCH_TICKET_INVALID', 'Game launch ticket is invalid or does not match this session')

    if ticket.consumed_at is not None:
        raise api_error(409, 'LAUNCH_TICKET_CONSUMED', 'Game launch ticket has already been consumed')

    if ticket.expires_at <= now:
        raise api_error(409, 'LAUNCH_TICKET_EXPIRED', 'Game launch ticket has expired')

    gs = db.get(GameSession, body.game_session_id)
    if not gs or gs.user_id != user.id or gs.auth_session_id != sess.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Associated game session not found')

    ticket.consumed_at = now
    if gs.state == 'PENDING':
        gs.state = 'ACTIVE'
        gs.last_heartbeat_at = now

    db.add(AuditEvent(event='LAUNCH_TICKET_CONSUMED', user_id=user.id, session_id=sess.id, metadata_json={'game_session_id': gs.id}))
    db.commit()

    return {'consumed': True, 'game_session_id': gs.id, 'state': gs.state}

@app.post('/games/{game_session_id}/heartbeat')
def heartbeat(game_session_id: str, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    gs = db.get(GameSession, game_session_id)
    now = utcnow()
    if not gs or gs.user_id != user.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Game session not found')
    if gs.auth_session_id != sess.id:
        raise api_error(409, 'GAME_SESSION_MISMATCH', 'Game session belongs to a different authentication session')
    if gs.state != 'ACTIVE':
        raise api_error(409, 'GAME_SESSION_REQUIRED', f'Game session is in {gs.state} state, active session required')
    if gs.expires_at <= now or (now - gs.last_heartbeat_at).total_seconds() > settings.game_heartbeat_grace_seconds:
        gs.state = 'EXPIRED'
        db.commit()
        raise api_error(409, 'GAME_SESSION_EXPIRED', 'Active game session heartbeat lease has expired')

    gs.last_heartbeat_at = now
    db.commit()
    return {'game_session_id': gs.id, 'state': gs.state, 'last_heartbeat_at': gs.last_heartbeat_at}

@app.post('/games/{game_session_id}/exit')
def exit_game(game_session_id: str, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    gs = db.get(GameSession, game_session_id)
    if not gs or gs.user_id != user.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Game session not found')
    if gs.auth_session_id != sess.id:
        raise api_error(409, 'GAME_SESSION_MISMATCH', 'Game session belongs to a different authentication session')
    gs.state = 'EXITED'
    gs.exit_at = utcnow()
    db.commit()
    return {'closed': True, 'state': gs.state}

@app.post('/games/{game_session_id}/settle')
def settle_game(game_session_id: str, body: SettleIn, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    gs = db.get(GameSession, game_session_id)
    if not gs or gs.user_id != user.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Game session not found')
    if gs.auth_session_id != sess.id:
        raise api_error(409, 'GAME_SESSION_MISMATCH', 'Game session belongs to a different authentication session')
    if gs.state not in ['ACTIVE', 'EXITED']:
        raise api_error(409, 'GAME_SESSION_REQUIRED', f'Cannot settle game session in state {gs.state}')

    nonce = ActionNonce(nonce=body.client_request_id, user_id=user.id, expires_at=now + timedelta(seconds=settings.action_token_ttl_seconds))
    db.add(nonce)
    try:
        db.flush()
    except Exception:
        db.rollback()
        raise api_error(409, 'REQUEST_REPLAYED', 'Settlement request ID has already been used')

    b = db.execute(select(Balance).where(Balance.user_id == user.id).with_for_update()).scalar_one()
    if body.payout_amount > 0:
        b.cash_available = float(Decimal(str(b.cash_available)) + body.payout_amount)
        b.version += 1
    gs.state = 'SETTLED'
    nonce.consumed_at = now
    db.add(
        AuditEvent(
            event='GAME_SESSION_SETTLED',
            user_id=user.id,
            session_id=sess.id,
            metadata_json={'game_session_id': gs.id, 'payout': str(body.payout_amount), 'balance_version': b.version},
        )
    )
    db.commit()
    return {
        'settled': True,
        'game_session_id': gs.id,
        'state': gs.state,
        'payout_amount': float(body.payout_amount),
        'balance_version': b.version,
    }

@app.get('/system/user-state')
def user_state(ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    p = db.scalar(
        select(PageState)
        .where(PageState.user_id == user.id, PageState.session_id == sess.id)
        .order_by(PageState.last_seen_at.desc())
    )
    b = db.get(Balance, user.id)
    gs = db.scalar(
        select(GameSession)
        .where(
            GameSession.user_id == user.id,
            GameSession.auth_session_id == sess.id,
            GameSession.state == 'ACTIVE',
        )
        .order_by(GameSession.created_at.desc())
    )

    fresh_page = bool(p and (now - p.last_seen_at).total_seconds() <= settings.page_stale_seconds)
    active_game = bool(
        gs
        and gs.expires_at > now
        and (now - gs.last_heartbeat_at).total_seconds() <= settings.game_heartbeat_grace_seconds
    )
    available = max(Decimal(str(b.cash_available)) - Decimal(str(b.locked_amount)), Decimal('0.00'))

    return {
        'user': {
            'id': user.id,
            'registered': True,
            'external_uid': user.external_uid,
            'shreewin_uid': user.external_uid,
            'invite_code': user.invite_code,
            'registered_at': user.registered_at,
        },
        'authentication': {
            'logged_in': True,
            'session_id': sess.id,
            'last_seen_at': sess.last_seen_at,
            'expires_at': sess.expires_at,
        },
        'page': {
            'route': p.route if p else None,
            'page_name': p.page_name if p else None,
            'last_reported_at': p.last_seen_at if p else None,
            'is_stale': not fresh_page,
        },
        'game': {
            'inside_game': active_game,
            'game_session_id': gs.id if active_game else None,
            'state': gs.state if active_game else None,
        },
        'balance': {
            'cash_available': float(b.cash_available),
            'bonus_available': float(b.bonus_available),
            'locked_amount': float(b.locked_amount),
            'available_for_game': float(available),
            'balance_version': b.version,
            'as_of': b.updated_at,
        },
    }

@app.post('/authorize-action')
def authorize(body: ActionIn, ctx=Depends(require_context), db: Session = Depends(get_db)):
    user, sess = ctx
    now = utcnow()
    gs = db.get(GameSession, body.game_session_id)
    b = db.get(Balance, user.id)

    if not gs or gs.user_id != user.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Game session not found')
    if gs.auth_session_id != sess.id:
        raise api_error(409, 'GAME_SESSION_MISMATCH', 'Game session belongs to a different authentication session')
    if gs.state != 'ACTIVE':
        raise api_error(409, 'GAME_SESSION_REQUIRED', 'A fresh active game session is required')
    if gs.expires_at <= now or (now - gs.last_heartbeat_at).total_seconds() > settings.game_heartbeat_grace_seconds:
        gs.state = 'EXPIRED'
        db.commit()
        raise api_error(409, 'GAME_SESSION_EXPIRED', 'Active game session heartbeat lease has expired')

    available = Decimal(str(b.cash_available)) - Decimal(str(b.locked_amount))
    if available < body.required_balance:
        raise api_error(
            409,
            'INSUFFICIENT_BALANCE',
            'Available balance is below the required amount',
            extra={'available_for_game': float(available)},
        )

    nonce = ActionNonce(nonce=body.client_request_id, user_id=user.id, expires_at=now + timedelta(seconds=settings.action_token_ttl_seconds))
    db.add(nonce)
    try:
        db.flush()
    except Exception:
        db.rollback()
        raise api_error(409, 'REQUEST_REPLAYED', 'Request ID has already been used')

    audit = ActionAuditRecord(
        action_id=new_id(),
        user_id=user.id,
        auth_session_id=sess.id,
        game_session_id=gs.id,
        operation='AUTHORIZE',
        request_id=body.client_request_id,
        amount=float(body.required_balance),
        balance_before=float(available),
        balance_after=float(available),
        balance_version=b.version,
        status='SUCCESS',
        created_at=now,
    )
    db.add(audit)
    db.add(
        AuditEvent(
            event='ACTION_AUTHORIZED',
            user_id=user.id,
            session_id=sess.id,
            metadata_json={'game_session_id': gs.id, 'balance_version': b.version, 'required_balance': str(body.required_balance)},
        )
    )
    db.commit()

    return {
        'allowed': True,
        'expires_at': nonce.expires_at,
        'user_id': user.id,
        'game_session_id': gs.id,
        'balance_version': b.version,
        'request_id': body.client_request_id,
    }

@app.post('/game-sessions/{game_session_id}/actions/{operation}')
def execute_game_action(
    game_session_id: str,
    operation: str,
    body: ActionExecuteIn,
    idempotency_key: str | None = Header(default=None, alias='Idempotency-Key'),
    ctx=Depends(require_context),
    db: Session = Depends(get_db),
):
    user, sess = ctx
    now = utcnow()

    # 1. Idempotency check
    idem_key = f"{user.id}:{operation}:{idempotency_key}" if idempotency_key else None
    if idem_key:
        cached = db.get(IdempotencyRecord, idem_key)
        if cached and cached.expires_at > now:
            return cached.response_json

    # 2. Game session & lease validation
    gs = db.get(GameSession, game_session_id)
    if not gs or gs.user_id != user.id:
        raise api_error(404, 'GAME_SESSION_REQUIRED', 'Game session not found')
    if gs.auth_session_id != sess.id:
        raise api_error(409, 'GAME_SESSION_MISMATCH', 'Game session belongs to a different authentication session')
    if gs.state != 'ACTIVE':
        raise api_error(409, 'GAME_SESSION_REQUIRED', f'Game session is {gs.state}, active session required')
    if gs.expires_at <= now or (now - gs.last_heartbeat_at).total_seconds() > settings.game_heartbeat_grace_seconds:
        gs.state = 'EXPIRED'
        db.commit()
        raise api_error(409, 'GAME_SESSION_EXPIRED', 'Active game session heartbeat lease expired')

    # 3. Request nonce consumption
    nonce = ActionNonce(nonce=body.client_request_id, user_id=user.id, expires_at=now + timedelta(seconds=settings.action_token_ttl_seconds))
    db.add(nonce)
    try:
        db.flush()
    except Exception:
        db.rollback()
        raise api_error(409, 'REQUEST_REPLAYED', 'Request ID has already been used')

    # 4. Row-level balance lock & verification
    b = db.execute(select(Balance).where(Balance.user_id == user.id).with_for_update()).scalar_one()
    available = Decimal(str(b.cash_available)) - Decimal(str(b.locked_amount))
    if available < body.amount:
        audit = ActionAuditRecord(
            action_id=new_id(),
            user_id=user.id,
            auth_session_id=sess.id,
            game_session_id=gs.id,
            operation=operation,
            request_id=body.client_request_id,
            idempotency_key=idempotency_key,
            amount=float(body.amount),
            balance_before=float(available),
            balance_after=float(available),
            balance_version=b.version,
            status='FAILED',
            failure_reason='INSUFFICIENT_BALANCE',
            created_at=now,
        )
        db.add(audit)
        db.commit()
        raise api_error(409, 'INSUFFICIENT_BALANCE', 'Available balance is below the required amount', extra={'available_for_game': float(available)})

    # 5. Atomic Debit & version bump
    bal_before = float(available)
    if body.amount > 0:
        b.cash_available = float(Decimal(str(b.cash_available)) - body.amount)
        b.version += 1
    bal_after = float(Decimal(str(b.cash_available)) - Decimal(str(b.locked_amount)))

    nonce.consumed_at = now
    action_id = new_id()
    audit = ActionAuditRecord(
        action_id=action_id,
        user_id=user.id,
        auth_session_id=sess.id,
        game_session_id=gs.id,
        operation=operation,
        request_id=body.client_request_id,
        idempotency_key=idempotency_key,
        amount=float(body.amount),
        balance_before=bal_before,
        balance_after=bal_after,
        balance_version=b.version,
        status='SUCCESS',
        created_at=now,
    )
    db.add(audit)

    result = {
        'action_id': action_id,
        'status': 'COMPLETED',
        'operation': operation,
        'debited_amount': float(body.amount),
        'balance_version': b.version,
        'available_balance': bal_after,
        'game_session_id': gs.id,
        'request_id': body.client_request_id,
    }

    # 6. Idempotency persistence
    if idem_key:
        idem_rec = IdempotencyRecord(
            key=idem_key,
            user_id=user.id,
            operation=operation,
            request_hash=hash_secret(body.client_request_id),
            status_code=200,
            response_json=result,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.idempotency_ttl_seconds),
        )
        db.add(idem_rec)

    db.commit()
    return result

# ------------------------------------------------------------------------------
# WinGo Public Game APIs (NO AUTHENTICATION REQUIRED)
# ------------------------------------------------------------------------------

class WingoIssueIn(BaseModel):
    type: str | int | None = None
    type_id: str | int | None = None
    typeId: str | int | None = None
    issue: str | None = None
    issue_number: str | None = None
    issueNumber: str | None = None

class WingoHistoryIn(BaseModel):
    type: str | int | None = None
    type_id: str | int | None = None
    page: int = 1
    size: int = 10

def _get_wingo_issue_data(type_id: int):
    resp = call_provider_api('/api/webapi/GetGameIssue', {'typeId': type_id})
    if not resp or resp.get('code') != 0 or not resp.get('data'):
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch current WinGo round') if resp else 'Provider unavailable')
    d = resp['data']
    remaining_seconds = None
    if d.get('endTime') and d.get('serviceTime'):
        try:
            end_t = datetime.strptime(d['endTime'], '%Y-%m-%d %H:%M:%S')
            serv_t = datetime.strptime(d['serviceTime'], '%Y-%m-%d %H:%M:%S')
            remaining_seconds = max(0, int((end_t - serv_t).total_seconds()))
        except Exception:
            pass
    return {
        'success': True,
        'auth_required': False,
        'type_id': type_id,
        'issue_number': d.get('issueNumber'),
        'start_time': d.get('startTime'),
        'end_time': d.get('endTime'),
        'server_time': d.get('serviceTime') or resp.get('serviceNowTime'),
        'interval_minutes': d.get('intervalM'),
        'countdown_seconds': remaining_seconds,
    }

def _get_wingo_history_data(type_id: int, page: int, size: int):
    page_size = min(50, max(1, size))
    resp = call_provider_api('/api/webapi/GetNoaverageEmerdList', {
        'typeId': type_id,
        'pageNo': page,
        'pageSize': page_size,
    })
    if not resp or resp.get('code') != 0 or not resp.get('data'):
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch WinGo history') if resp else 'Provider unavailable')
    data = resp['data']
    results = [enrich_wingo_result(item) for item in data.get('list', [])]
    return {
        'success': True,
        'auth_required': False,
        'type_id': type_id,
        'page_no': data.get('pageNo', page),
        'total_page': data.get('totalPage', 0),
        'total_count': data.get('totalCount', 0),
        'results': results,
    }

@app.get('/games/wingo/types')
@app.get('/wingo/types')
@app.post('/games/wingo/types')
@app.post('/wingo/types')
def wingo_types():
    resp = call_provider_api('/api/webapi/GetTypeList', {})
    if not resp or resp.get('code') != 0 or not resp.get('data'):
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch WinGo game types') if resp else 'Provider unavailable')
    types = [
        {
            'type_id': item.get('typeID'),
            'type_name': item.get('typeName'),
            'interval_minutes': item.get('intervalM'),
            'game_code': item.get('gameCode'),
            'bet_scope': [int(x) for x in item.get('scope', '').split('|') if x.isdigit()] if item.get('scope') else [],
            'multipliers': [int(x) for x in item.get('betMultiple', '').split('|') if x.isdigit()] if item.get('betMultiple') else [],
        }
        for item in resp['data']
    ]
    return {
        'success': True,
        'auth_required': False,
        'server_time': resp.get('serviceNowTime') or utcnow().isoformat(),
        'types': types,
    }

@app.get('/games/wingo/issue')
@app.get('/wingo/issue')
def wingo_issue_get(type: str | None = None, type_id: str | None = None):
    type_val = parse_wingo_type_id(type_id or type or 1)
    return _get_wingo_issue_data(type_val)

@app.post('/games/wingo/issue')
@app.post('/wingo/issue')
def wingo_issue_post(body: WingoIssueIn | None = None):
    raw = body.type_id if body and body.type_id is not None else (body.type if body else 1)
    type_val = parse_wingo_type_id(raw or 1)
    return _get_wingo_issue_data(type_val)

@app.get('/games/wingo/history')
@app.get('/wingo/history')
def wingo_history_get(type: str | None = None, type_id: str | None = None, page: int = 1, size: int = 10):
    type_val = parse_wingo_type_id(type_id or type or 1)
    return _get_wingo_history_data(type_val, page, size)

@app.post('/games/wingo/history')
@app.post('/wingo/history')
def wingo_history_post(body: WingoHistoryIn | None = None):
    raw = body.type_id if body and body.type_id is not None else (body.type if body else 1)
    type_val = parse_wingo_type_id(raw or 1)
    page = body.page if body else 1
    size = body.size if body else 10
    return _get_wingo_history_data(type_val, page, size)

@app.get('/games/wingo/recent-results')
@app.get('/wingo/recent-results')
@app.post('/games/wingo/recent-results')
@app.post('/wingo/recent-results')
def wingo_recent(type: str | None = None, type_id: str | None = None):
    type_val = parse_wingo_type_id(type_id or type or 1)
    resp = call_provider_api('/api/webapi/GetLastFiveIssueNumberResult', {'typeId': type_val})
    if not resp or resp.get('code') != 0:
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch recent results') if resp else 'Provider unavailable')
    data = resp.get('data') or {}
    return {
        'success': True,
        'auth_required': False,
        'type_id': type_val,
        'numbers': data.get('number', []),
    }

@app.get('/games/wingo/rules')
@app.get('/wingo/rules')
@app.post('/games/wingo/rules')
@app.post('/wingo/rules')
def wingo_rules(type: str | None = None, type_id: str | None = None):
    type_val = parse_wingo_type_id(type_id or type or 1)
    resp = call_provider_api('/api/webapi/GetRuleByTypeId', {'typeId': type_val})
    if not resp or resp.get('code') != 0:
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch WinGo rules') if resp else 'Provider unavailable')
    data = resp.get('data') or {}
    return {
        'success': True,
        'auth_required': False,
        'type_id': type_val,
        'presentation': data.get('gamePresentation'),
    }

@app.get('/games/wingo/trx/types')
@app.get('/wingo/trx/types')
@app.post('/games/wingo/trx/types')
@app.post('/wingo/trx/types')
def wingo_trx_types():
    resp = call_provider_api('/api/webapi/GetTRXtypeList', {})
    if not resp or resp.get('code') != 0 or not resp.get('data'):
        raise api_error(502, 'PROVIDER_UNAVAILABLE', resp.get('msg', 'Failed to fetch TRX WinGo types') if resp else 'Provider unavailable')
    types = [
        {
            'type_id': item.get('typeID'),
            'type_name': item.get('typeName'),
            'interval_minutes': item.get('intervalM'),
            'game_code': item.get('gameCode'),
            'bet_scope': [int(x) for x in item.get('scope', '').split('|') if x.isdigit()] if item.get('scope') else [],
            'multipliers': [int(x) for x in item.get('betMultiple', '').split('|') if x.isdigit()] if item.get('betMultiple') else [],
        }
        for item in resp['data']
    ]
    return {
        'success': True,
        'auth_required': False,
        'types': types,
    }

@app.get('/games/wingo/live-stream')
@app.get('/wingo/live-stream')
async def wingo_live_stream(request: Request, type: str | None = None, type_id: str | None = None, limit: int | None = None):
    type_val = parse_wingo_type_id(type_id or type or 1)

    async def event_generator():
        # 1. Connection acknowledgement
        yield f"event: connected\ndata: {json.dumps({'status': 'live', 'type_id': type_val, 'connected_at': utcnow().isoformat()})}\n\n"

        # 2. Initial round snapshot
        issue_resp = call_provider_api('/api/webapi/GetGameIssue', {'typeId': type_val})
        d = issue_resp.get('data') or {}
        current_issue = d.get('issueNumber')
        remaining_seconds = 60
        if d.get('endTime') and d.get('serviceTime'):
            try:
                end_t = datetime.strptime(d['endTime'], '%Y-%m-%d %H:%M:%S')
                serv_t = datetime.strptime(d['serviceTime'], '%Y-%m-%d %H:%M:%S')
                remaining_seconds = max(0, int((end_t - serv_t).total_seconds()))
            except Exception:
                pass

        yield f"event: tick\ndata: {json.dumps({'type_id': type_val, 'issue_number': current_issue, 'countdown_seconds': remaining_seconds, 'server_time': d.get('serviceTime') or utcnow().isoformat()})}\n\n"

        ticks_sent = 0
        while not await request.is_disconnected():
            if limit is not None and ticks_sent >= limit:
                break
            await asyncio.sleep(1)
            remaining_seconds -= 1
            ticks_sent += 1

            if remaining_seconds <= 0:
                yield f"event: round_ended\ndata: {json.dumps({'type_id': type_val, 'issue_number': current_issue, 'ended_at': utcnow().isoformat()})}\n\n"

                try:
                    new_issue = call_provider_api('/api/webapi/GetGameIssue', {'typeId': type_val})
                    history_resp = call_provider_api('/api/webapi/GetNoaverageEmerdList', {'typeId': type_val, 'pageNo': 1, 'pageSize': 1})

                    if history_resp.get('data', {}).get('list'):
                        result_item = enrich_wingo_result(history_resp['data']['list'][0])
                        yield f"event: result\ndata: {json.dumps(result_item)}\n\n"

                    d_new = new_issue.get('data') or {}
                    current_issue = d_new.get('issueNumber')
                    if d_new.get('endTime') and d_new.get('serviceTime'):
                        try:
                            end_t = datetime.strptime(d_new['endTime'], '%Y-%m-%d %H:%M:%S')
                            serv_t = datetime.strptime(d_new['serviceTime'], '%Y-%m-%d %H:%M:%S')
                            remaining_seconds = max(0, int((end_t - serv_t).total_seconds()))
                        except Exception:
                            remaining_seconds = 30 if type_val == 30 else 60
                    else:
                        remaining_seconds = 30 if type_val == 30 else 60
                except Exception:
                    remaining_seconds = 30 if type_val == 30 else 60

            yield f"event: tick\ndata: {json.dumps({'type_id': type_val, 'issue_number': current_issue, 'countdown_seconds': remaining_seconds, 'server_time': utcnow().isoformat()})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


# ------------------------------------------------------------------------------
# Dynamic Remote OTA Config Engine (/app/config, /api/config, /admin/app-config)
# ------------------------------------------------------------------------------

class AppConfigIn(BaseModel):
    channel: str = 'default'
    app_active: bool | None = None
    min_unlock_balance: float | None = None
    whitelisted_users: list | None = None
    blacklisted_users: list | None = None
    broadcast_notice: str | None = None
    broadcast_priority: str | None = None
    deposit_url: str | None = None
    register_url: str | None = None
    bubble_icon_url: str | None = None
    branding_panel_name: str | None = None
    branding_bubble_label: str | None = None
    branding_theme_color: str | None = None
    win_feed_enabled: bool | None = None
    strict_reg_lock: bool | None = None

def _get_or_create_channel_config(db: Session, channel_key: str) -> AppConfigRecord:
    chan = channel_key.strip().lower() if channel_key else 'default'
    cfg = db.execute(select(AppConfigRecord).where(AppConfigRecord.channel == chan)).scalar_one_or_none()
    if not cfg:
        if chan != 'default':
            default_cfg = db.execute(select(AppConfigRecord).where(AppConfigRecord.channel == 'default')).scalar_one_or_none()
            if default_cfg:
                return default_cfg
        cfg = AppConfigRecord(
            channel=chan,
            app_active=True,
            min_unlock_balance=50.0,
            whitelisted_users=[],
            blacklisted_users=[],
            broadcast_notice="Welcome • Signals are entertainment only • 18+ play responsibly",
            broadcast_priority="important",
            deposit_url="https://www.shreewin.ai/#/wallet/Recharge",
            register_url="https://www.shreewin6.com/#/register?invitationCode=78763141420",
            bubble_icon_url="https://i.ibb.co/fGpr57nL/20260904-132124.webp",
            branding_panel_name="NEXY",
            branding_bubble_label="NEXY",
            branding_theme_color="#8C25E3",
            win_feed_enabled=True,
            strict_reg_lock=False,
            version="2.0.0",
            updated_at=utcnow(),
        )
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg

def _format_config_response(cfg: AppConfigRecord) -> dict:
    return {
        "channel": cfg.channel,
        "app_active": cfg.app_active,
        "min_unlock_balance": float(cfg.min_unlock_balance or 50.0),
        "whitelisted_users": cfg.whitelisted_users or [],
        "blacklisted_users": cfg.blacklisted_users or [],
        "broadcast_notice": cfg.broadcast_notice,
        "broadcast_priority": cfg.broadcast_priority,
        "deposit_url": cfg.deposit_url,
        "register_url": cfg.register_url,
        "bubble_icon_url": cfg.bubble_icon_url,
        "branding": {
            "panel_name": cfg.branding_panel_name,
            "bubble_label": cfg.branding_bubble_label,
            "theme_color": cfg.branding_theme_color,
        },
        "win_feed": {
            "enabled": cfg.win_feed_enabled,
            "min_interval_s": 7,
            "max_interval_s": 14,
            "visible_s": 3.6,
            "first_delay_s": 4.5,
        },
        "strict_reg_lock": cfg.strict_reg_lock,
        "target_games": ["WinGo 30s", "WinGo 1 Min", "WinGo 3 Min", "WinGo 5 Min"],
        "version": cfg.version,
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else utcnow().isoformat(),
    }

@app.get('/app/config')
@app.get('/api/config')
def get_app_config(channel: str = 'default', did: str | None = None, v: str | None = None, db: Session = Depends(get_db)):
    cfg = _get_or_create_channel_config(db, channel)
    return _format_config_response(cfg)

@app.post('/admin/app-config')
@app.post('/api/admin/config')
def update_app_config(body: AppConfigIn, db: Session = Depends(get_db)):
    chan = (body.channel or 'default').strip().lower()
    cfg = db.execute(select(AppConfigRecord).where(AppConfigRecord.channel == chan)).scalar_one_or_none()
    if not cfg:
        cfg = _get_or_create_channel_config(db, chan)

    if body.app_active is not None: cfg.app_active = body.app_active
    if body.min_unlock_balance is not None: cfg.min_unlock_balance = Decimal(str(body.min_unlock_balance))
    if body.whitelisted_users is not None: cfg.whitelisted_users = body.whitelisted_users
    if body.blacklisted_users is not None: cfg.blacklisted_users = body.blacklisted_users
    if body.broadcast_notice is not None: cfg.broadcast_notice = body.broadcast_notice
    if body.broadcast_priority is not None: cfg.broadcast_priority = body.broadcast_priority
    if body.deposit_url is not None: cfg.deposit_url = body.deposit_url
    if body.register_url is not None: cfg.register_url = body.register_url
    if body.bubble_icon_url is not None: cfg.bubble_icon_url = body.bubble_icon_url
    if body.branding_panel_name is not None: cfg.branding_panel_name = body.branding_panel_name
    if body.branding_bubble_label is not None: cfg.branding_bubble_label = body.branding_bubble_label
    if body.branding_theme_color is not None: cfg.branding_theme_color = body.branding_theme_color
    if body.win_feed_enabled is not None: cfg.win_feed_enabled = body.win_feed_enabled
    if body.strict_reg_lock is not None: cfg.strict_reg_lock = body.strict_reg_lock

    try:
        parts = cfg.version.split('.')
        parts[-1] = str(int(parts[-1]) + 1)
        cfg.version = '.'.join(parts)
    except Exception:
        cfg.version = '2.0.1'

    cfg.updated_at = utcnow()
    db.commit()
    db.refresh(cfg)
    return {"success": True, "message": f"Config updated for channel '{chan}'", "config": _format_config_response(cfg)}


# ------------------------------------------------------------------------------
# Live Device Telemetry & Whale Tracking (/api/heartbeat, /api/check-user, /admin/telemetry)
# ------------------------------------------------------------------------------

class HeartbeatIn(BaseModel):
    userId: str | int | None = None
    userName: str | None = None
    phone: str | None = None
    balance: float = 0.0
    game: str = 'WinGo 1-Min'
    state: str = 'STATE_LIVE_WINGO'
    channel: str = 'default'
    device: dict | None = None

class CheckUserIn(BaseModel):
    userId: str | int | None = None
    phone: str | None = None
    channel: str = 'default'

@app.post('/api/heartbeat')
def ingest_heartbeat(body: HeartbeatIn, request: Request, db: Session = Depends(get_db)):
    raw_uid = str(body.userId or '').strip()
    client_ip = request.client.host if request.client else '127.0.0.1'
    uid = raw_uid or f"guest_{abs(hash(client_ip)) % 1000000:06d}"

    dev = body.device or {}
    dev_id = str(dev.get('deviceId') or '').strip()[:32] or 'nodesvice'
    session_key = f"{uid}|{dev_id}"

    rec = db.execute(select(DeviceTelemetryRecord).where(DeviceTelemetryRecord.id == session_key)).scalar_one_or_none()
    now = utcnow()

    num_bal = max(0.0, float(body.balance or 0.0))
    is_emu = bool(dev.get('isEmulator', False))
    is_root = bool(dev.get('isRooted', False))
    risk = 'emulator' if is_emu else ('rooted' if is_root else '')

    if not rec:
        rec = DeviceTelemetryRecord(
            id=session_key,
            user_id=uid,
            user_name=body.userName or '',
            phone=body.phone or '',
            balance=num_bal,
            peak_balance=num_bal,
            game=body.game or 'WinGo 1-Min',
            state=body.state or ('STATE_LIVE_WINGO' if num_bal >= 50 else 'STATE_DEPOSIT_LOCKED'),
            device_id=dev_id if dev_id != 'nodesvice' else None,
            device_brand=str(dev.get('brand') or '') or None,
            device_model=str(dev.get('model') or '') or None,
            device_os=str(dev.get('osVersion') or '') or None,
            is_emulator=is_emu,
            is_rooted=is_root,
            risk=risk,
            channel=(body.channel or 'default').strip().lower(),
            ip=client_ip,
            first_seen_at=now,
            last_seen_at=now,
            logins=1,
            total_pings=1,
        )
        db.add(rec)
    else:
        if (now - rec.last_seen_at).total_seconds() > 1800:
            rec.logins += 1
        rec.balance = num_bal
        rec.peak_balance = max(float(rec.peak_balance or 0.0), num_bal)
        rec.user_name = body.userName or rec.user_name
        rec.phone = body.phone or rec.phone
        rec.game = body.game or rec.game
        rec.state = body.state or rec.state
        rec.is_emulator = is_emu or rec.is_emulator
        rec.is_rooted = is_root or rec.is_rooted
        rec.risk = risk or rec.risk
        rec.channel = (body.channel or rec.channel or 'default').strip().lower()
        rec.ip = client_ip
        rec.last_seen_at = now
        rec.total_pings += 1

    db.commit()
    db.refresh(rec)
    return {
        "success": True,
        "id": rec.id,
        "balance": float(rec.balance),
        "peak_balance": float(rec.peak_balance),
        "total_pings": rec.total_pings,
    }

@app.post('/api/check-user')
def check_user(body: CheckUserIn, db: Session = Depends(get_db)):
    uid = str(body.userId or '').strip()
    phone = str(body.phone or '').strip()
    chan = (body.channel or 'default').strip().lower()

    cfg = _get_or_create_channel_config(db, chan)
    whitelisted = cfg.whitelisted_users or []
    blacklisted = cfg.blacklisted_users or []

    # 1. Check blacklist
    if (uid and uid in blacklisted) or (phone and phone in blacklisted):
        return {
            "allowed": False,
            "status": "Banned",
            "is_vip": False,
            "unlocked": False,
            "reason": "Account is restricted by administration."
        }

    # 2. Check whitelist (VIP bypass)
    if (uid and uid in whitelisted) or (phone and phone in whitelisted):
        return {
            "allowed": True,
            "status": "VIP",
            "is_vip": True,
            "unlocked": True,
            "reason": "Whitelisted VIP player."
        }

    # 3. Check live balance from telemetry or D1 balances
    current_balance = 0.0
    if uid:
        try:
            numeric_uid = int(uid)
            bal_rec = db.execute(select(Balance).where(Balance.user_id == numeric_uid)).scalar_one_or_none()
            if bal_rec:
                current_balance = float(bal_rec.cash_available or 0.0)
        except ValueError:
            pass

    if current_balance <= 0.0:
        telemetry = db.execute(select(DeviceTelemetryRecord).where(DeviceTelemetryRecord.user_id == uid)).scalars().all()
        if telemetry:
            current_balance = max([float(t.balance or 0.0) for t in telemetry])

    min_bal = float(cfg.min_unlock_balance or 50.0)
    unlocked = current_balance >= min_bal

    # 4. Strict registration lock check
    if cfg.strict_reg_lock and not unlocked:
        return {
            "allowed": False,
            "status": "RegistrationLocked",
            "is_vip": False,
            "unlocked": False,
            "balance": current_balance,
            "min_required_balance": min_bal,
            "reason": "Official app referral registration required to unlock live predictions."
        }

    return {
        "allowed": True,
        "status": "Deposited" if unlocked else "Locked",
        "is_vip": False,
        "unlocked": unlocked,
        "balance": current_balance,
        "min_required_balance": min_bal,
        "reason": "Active player session." if unlocked else f"Minimum balance of {min_bal} required."
    }

@app.get('/admin/telemetry')
@app.get('/api/admin/live-players')
def get_admin_telemetry(channel: str = 'all', db: Session = Depends(get_db)):
    stmt = select(DeviceTelemetryRecord)
    if channel != 'all':
        stmt = stmt.where(DeviceTelemetryRecord.channel == channel.strip().lower())
    records = db.execute(stmt).scalars().all()

    now = utcnow()
    active_players = [r for r in records if (now - r.last_seen_at).total_seconds() <= 120]
    whales = sorted(records, key=lambda r: float(r.balance or 0.0), reverse=True)

    total_capital = sum(float(r.balance or 0.0) for r in records)
    top_balance = max([float(r.balance or 0.0) for r in records], default=0.0)
    game_breakdown: dict[str, int] = {}
    for r in records:
        g = r.game or 'WinGo 1-Min'
        game_breakdown[g] = game_breakdown.get(g, 0) + 1

    return {
        "summary": {
            "total_tracked": len(records),
            "online_now": len(active_players),
            "total_capital": round(total_capital, 2),
            "top_whale_balance": round(top_balance, 2),
            "game_breakdown": game_breakdown,
        },
        "whales": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "user_name": r.user_name,
                "phone": r.phone,
                "balance": float(r.balance),
                "peak_balance": float(r.peak_balance),
                "game": r.game,
                "risk": r.risk,
                "channel": r.channel,
                "last_seen_at": r.last_seen_at.isoformat(),
            }
            for r in whales[:50]
        ],
        "live_active": [
            {
                "user_id": r.user_id,
                "game": r.game,
                "balance": float(r.balance),
                "device": f"{r.device_brand or ''} {r.device_model or ''}".strip(),
                "last_seen_seconds_ago": int((now - r.last_seen_at).total_seconds()),
            }
            for r in active_players
        ]
    }


# ------------------------------------------------------------------------------
# Server-Authoritative WinGo Predictor & Trend Engine (/games/wingo/prediction)
# ------------------------------------------------------------------------------

def _generate_wingo_prediction(type_id: int, issue_number: str | None = None) -> dict:
    import hashlib
    type_names = {10: 'WinGo 30s', 1: 'WinGo 1-Min', 2: 'WinGo 3-Min', 3: 'WinGo 5-Min'}
    game_name = type_names.get(type_id, f'WinGo Type {type_id}')

    current_issue = issue_number
    if not current_issue:
        try:
            issue_resp = call_provider_api('/api/webapi/GetGameIssue', {'typeId': type_id})
            current_issue = issue_resp.get('data', {}).get('issueNumber')
        except Exception:
            pass
    if not current_issue:
        current_issue = f"{utcnow().strftime('%Y%m%d')}1000"

    # Fetch recent history
    history = []
    try:
        history_resp = call_provider_api('/api/webapi/GetNoaverageEmerdList', {'typeId': type_id, 'pageNo': 1, 'pageSize': 15})
        raw_list = history_resp.get('data', {}).get('list') or []
        history = [enrich_wingo_result(item) for item in raw_list]
    except Exception:
        pass

    if history:
        sizes = [h.get('size') for h in history if h.get('size')]
        colors = [h.get('color') for h in history if h.get('color')]

        latest_size = sizes[0] if sizes else 'BIG'
        streak_count = 1
        for s in sizes[1:]:
            if s == latest_size:
                streak_count += 1
            else:
                break

        if streak_count >= 3:
            predicted_size = latest_size
            streak_type = "FOLLOW_DRAGON"
            confidence = min(97.2, 87.5 + (streak_count * 1.8))
            analysis = f"{latest_size} Dragon momentum identified ({streak_count} consecutive rounds). Statistical probability favors continuation."
        elif len(sizes) >= 3 and sizes[0] != sizes[1] and sizes[1] == sizes[2]:
            predicted_size = 'SMALL' if sizes[0] == 'BIG' else 'BIG'
            streak_type = "CHOP_ALTERNATION"
            confidence = 89.4
            streak_count = 2
            analysis = "Alternating chop trend detected. Anticipating immediate alternation."
        else:
            predicted_size = 'BIG' if latest_size == 'SMALL' else 'SMALL'
            streak_type = "TREND_REVERSAL"
            confidence = 88.0
            streak_count = 1
            analysis = "Standard trend balance cycle projected."

        latest_color = colors[0] if colors else ('GREEN' if predicted_size == 'BIG' else 'RED')
        if latest_color == 'VIOLET':
            predicted_color = 'GREEN' if predicted_size == 'BIG' else 'RED'
        else:
            predicted_color = latest_color

        if predicted_size == 'BIG':
            recommended_numbers = [7, 9] if predicted_color == 'GREEN' else [6, 8]
        else:
            recommended_numbers = [1, 3] if predicted_color == 'GREEN' else [2, 4]

    else:
        seed = f"{type_id}:{current_issue}"
        hash_val = int(hashlib.sha256(seed.encode()).hexdigest(), 16)

        predicted_size = 'BIG' if (hash_val % 2 == 1) else 'SMALL'
        predicted_color = 'GREEN' if (hash_val % 3 == 0) else ('RED' if hash_val % 3 == 1 else 'VIOLET')
        confidence = 88.0 + (hash_val % 85) / 10.0
        streak_count = (hash_val % 4) + 1
        streak_type = "ALGORITHMIC_MODEL"
        recommended_numbers = [7, 9] if predicted_size == 'BIG' else [2, 4]
        analysis = "Algorithmic momentum projection generated via period seed engine."

    return {
        "success": True,
        "game_type": game_name,
        "type_id": type_id,
        "issue_number": current_issue,
        "prediction": {
            "size": str(predicted_size).upper(),
            "color": str(predicted_color).upper(),
            "recommended_numbers": recommended_numbers,
            "confidence_rate": round(confidence, 1),
            "streak_type": streak_type,
            "streak_count": streak_count,
            "analysis": analysis,
        },
        "timestamp": int(utcnow().timestamp())
    }


@app.get('/games/wingo/prediction')
@app.get('/wingo/prediction')
def wingo_prediction_get(
    type: str | None = None,
    type_id: str | None = None,
    typeId: str | None = None,
    issue: str | None = None,
    issue_number: str | None = None,
    issueNumber: str | None = None,
):
    type_val = parse_wingo_type_id(type_id or typeId or type or 1)
    target_issue = issue_number or issueNumber or issue
    return _generate_wingo_prediction(type_val, target_issue)

@app.post('/games/wingo/prediction')
@app.post('/wingo/prediction')
def wingo_prediction_post(body: WingoIssueIn | None = None):
    raw = (body.type_id or body.typeId or body.type) if body else 1
    type_val = parse_wingo_type_id(raw or 1)
    target_issue = (body.issue_number or body.issueNumber or body.issue) if body else None
    return _generate_wingo_prediction(type_val, target_issue)




