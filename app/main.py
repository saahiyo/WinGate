from contextlib import asynccontextmanager
from datetime import timedelta
from decimal import Decimal
import secrets

from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
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
    return {'status': 'ok', 'environment': settings.environment}

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

    return {
        'game_session_id': gid,
        'state': gs.state,
        'expires_at': gs.expires_at,
        'launch_ticket': raw_ticket,
        'ticket_expires_at': ticket.expires_at,
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
