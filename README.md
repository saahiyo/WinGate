# User State Authorization API

An authoritative, production-ready FastAPI service designed to enforce server-side validation for:
1. **User Identity & Registration** (Argon2 password hashing, referral/invite code tracking)
2. **Session Authentication** (Short-lived JWTs, rotating refresh tokens with reuse-attack detection)
3. **Wallet Balance** (Fresh ledger snapshots, concurrency-safe row-level atomic debits)
4. **Active Game Sessions** (Cryptographic single-use launch tickets, heartbeat leases, fail-closed verification)
5. **Client Page Telemetry** (Informational route & tab tracking with automatic stale-detection)
6. **Replay-Protected Protected Actions** (Client idempotency keys and atomic balance reservation)

> **Security Guarantee:** The backend is 100% authoritative. Browser `localStorage`, cookies, frontend routing URLs (e.g., `/game`), or client-reported states are **never** treated as proof of authentication or game activity.

---

## Architecture & Lifecycle Flow

```text
[Register / Invite]  -->  [Login & AuthSession]  -->  [Wallet Query]
                                  |
                                  v
[Page Telemetry]     -->  [Launch Game Ticket]   -->  [Consume Ticket & Active Lease]
                                                            |
                                                            v
                                            [Atomic Action & Balance Debit]
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (compatible with Python 3.11, 3.12, 3.13, 3.14)
- PowerShell (Windows) or Bash (macOS / Linux)

### 2. Environment Setup

```powershell
# Clone or navigate to the directory
cd user_state_api

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On Windows
# source .venv/bin/activate    # On Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Create environment configuration
Copy-Item .env.example .env    # On Windows
# cp .env.example .env         # On Linux/macOS
```

### 3. Start the Server

```powershell
uvicorn app.main:app --reload --port 8000
```

The service will start at **`http://127.0.0.1:8000`**.
Interactive Swagger documentation is available at **`http://127.0.0.1:8000/docs`**.

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `User State Authorization API` | Name of application |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DATABASE_URL` | `sqlite:///./user_state.db` | Database URL (`sqlite:///...` or `postgresql+psycopg://...`) |
| `JWT_SECRET_KEY` | `replace-this-with-a-long-random-secret` | 32+ character entropy secret key |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_MINUTES` | `15` | Expiry duration for JWT access tokens |
| `REFRESH_TOKEN_DAYS` | `30` | Expiry duration for refresh token family |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum required password characters |
| `PAGE_STALE_SECONDS` | `120` | Threshold after which client page telemetry is marked stale |
| `GAME_HEARTBEAT_GRACE_SECONDS`| `90` | Maximum interval allowed between game heartbeats before lease expires |
| `GAME_SESSION_TTL_SECONDS` | `3600` | Maximum absolute lifetime of a game session |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed frontend origins (never use `*` with credentials in production) |

---

## Step-by-Step API Usage Guide

### 1. Register an Account (`POST /auth/register`)
Creates a new user, initializes a 0.00 ledger balance, and logs a `USER_REGISTERED` audit event.

```http
POST /auth/register
Content-Type: application/json

{
  "identifier": "+917977200831",
  "password": "yourPassword123",
  "invite_code": "56541102022"
}
```
**Response (201 Created):**
```json
{
  "user_id": 1,
  "registered": true,
  "registered_at": "2026-09-08T15:29:11.965076",
  "invite_code": "56541102022"
}
```

---

### 2. User Login (`POST /auth/login`)
Validates credentials against Argon2 hashes and generates a short-lived access JWT and revocable refresh token.

```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "+917977200831",
  "password": "yourPassword123",
  "device_id": "mobile-android-device"
}
```
**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "refresh_token": "f4qgWd0Jx0...",
  "session_id": "cdc1549984674b21989485de8c54708a",
  "user_id": 1,
  "expires_at": "2026-09-08T15:44:11"
}
```

---

### 3. Verify Session Status (`GET /me`)
Validates the token signature and verifies that the server session has not been revoked or timed out.

```http
GET /me
Authorization: Bearer <ACCESS_TOKEN>
```
**Response (200 OK):**
```json
{
  "authenticated": true,
  "user_id": 1,
  "session_id": "cdc1549984674b21989485de8c54708a",
  "invite_code": "56541102022",
  "registered_at": "2026-09-08T15:29:11.965076",
  "session_expires_at": "2026-10-08T15:29:12.061125",
  "last_seen_at": "2026-09-08T15:29:12.097051"
}
```

---

### 4. Page View Telemetry (`POST /telemetry/page-view`)
The frontend reports route/tab changes. Marked stale if inactive longer than `PAGE_STALE_SECONDS`.

```http
POST /telemetry/page-view
Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json

{
  "route": "/casino/roulette",
  "page_name": "Live European Roulette",
  "tab_id": "tab-win-01"
}
```

---

### 5. Launch Game & Enter Session

To enter a game, the client requests a ticket and exchanges it for an active lease:

1. **Request Launch Ticket (`POST /games/launch`)**:
   ```http
   POST /games/launch
   Authorization: Bearer <ACCESS_TOKEN>
   Content-Type: application/json

   {
     "game_id": "roulette-pro",
     "vendor": "internal"
   }
   ```
   *Returns a single-use `launch_ticket` (valid for 120s).*

2. **Consume Ticket & Activate Game Lease (`POST /games/tickets/consume`)**:
   ```http
   POST /games/tickets/consume
   Authorization: Bearer <ACCESS_TOKEN>
   Content-Type: application/json

   {
     "game_session_id": "e8dd687426e94ba59d761bd8f59f0a3b",
     "launch_ticket": "f4qgWd0Jx0QxWskwS53RlDhEUSGwfEaYlW9ICcYsdWs"
   }
   ```
   *Status transitions to `ACTIVE`.*

3. **Game Heartbeat (`POST /games/{id}/heartbeat`)**:
   Must be called periodically by the game client/provider within `GAME_HEARTBEAT_GRACE_SECONDS` to renew the active lease.

---

### 6. Combined Authoritative Status (`GET /system/user-state`)
Single endpoint providing the complete verified state of the user.

```http
GET /system/user-state
Authorization: Bearer <ACCESS_TOKEN>
```
**Response (200 OK):**
```json
{
  "user": {
    "id": 1,
    "registered": true,
    "invite_code": "56541102022",
    "registered_at": "2026-09-08T15:29:11.965076"
  },
  "authentication": {
    "logged_in": true,
    "session_id": "cdc1549984674b21989485de8c54708a",
    "last_seen_at": "2026-09-08T15:29:12.179585",
    "expires_at": "2026-10-08T15:29:12.061125"
  },
  "page": {
    "route": "/casino/roulette",
    "page_name": "Live European Roulette",
    "last_reported_at": "2026-09-08T15:29:12.100000",
    "is_stale": false
  },
  "game": {
    "inside_game": true,
    "game_session_id": "e8dd687426e94ba59d761bd8f59f0a3b",
    "state": "ACTIVE"
  },
  "balance": {
    "cash_available": 0.0,
    "bonus_available": 0.0,
    "locked_amount": 0.0,
    "available_for_game": 0.0,
    "balance_version": 1,
    "as_of": "2026-09-08T15:29:11.971636"
  }
}
```

---

## All Endpoints Reference

| Method | Path | Auth Required | Description |
|---|---|:---:|---|
| `GET` | `/healthz` | No | Service health check |
| `POST` | `/auth/register` | No | Register new account with identifier, password, invite code |
| `POST` | `/auth/login` | No | Authenticate user, start session & issue token family |
| `POST` | `/auth/refresh` | No | Rotate tokens; revokes family if reuse attack detected |
| `POST` | `/auth/logout` | Yes | Revoke server session, refresh family, and all game leases |
| `GET` | `/me` | Yes | Validate active session and identity details |
| `GET` | `/wallet/available-balance` | Yes | Fresh balance breakdown (`cash`, `bonus`, `locked`) |
| `POST` | `/telemetry/page-view` | Yes | Record frontend route telemetry |
| `POST` | `/games/launch` | Yes | Create game session and single-use launch ticket |
| `POST` | `/games/tickets/consume` | Yes | Consume launch ticket and activate game session lease |
| `POST` | `/games/{id}/heartbeat` | Yes | Renew heartbeat lease for an active game session |
| `POST` | `/games/{id}/exit` | Yes | Close game session cleanly |
| `POST` | `/games/{id}/settle` | Yes | Settle game round and credit payout |
| `GET` | `/system/user-state` | Yes | Full authoritative state snapshot |
| `POST` | `/authorize-action` | Yes | Evaluate authorization & issue action token |
| `POST` | `/game-sessions/{id}/actions/{op}` | Yes | Atomic protected action execution & idempotent debit |

---

## Running Tests

The test suite covers full lifecycle validation, refresh-token rotation, reuse detection, heartbeat expiration, and multithreaded double-spend concurrency prevention:

```powershell
.\.venv\Scripts\pytest.exe -v
```

---

## Production Deployment Checklist

1. **Database:** Set `DATABASE_URL` to a production PostgreSQL instance (e.g. `postgresql+psycopg://user:password@host:5432/dbname`).
2. **Secrets:** Generate a 64-character random string (`openssl rand -hex 32`) for `JWT_SECRET_KEY`.
3. **CORS:** Restrict `CORS_ORIGINS` to exact trusted frontend domains (do not use `*` with credentials).
4. **HTTPS:** Terminate SSL/TLS at a reverse proxy (Nginx, Caddy, Cloudflare).
5. **Run Command:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
   ```
