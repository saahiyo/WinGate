# User State Authorization API & Platform Gateway

An authoritative, multi-client state authorization gateway and gaming integration platform designed to enforce server-side validation for:

1. **User Identity & Upstream Sync** (Argon2 / PBKDF2 hashing, dynamic external client synchronization, `external_uid` mapping)
2. **Session Authentication & Token Security** (Short-lived JWTs, rotating refresh tokens with automatic reuse-attack detection)
3. **Wallet Balance & Concurrency Safety** (Real-time balance snapshots, optimistic versioning, concurrency-safe atomic debits)
4. **Active Game Sessions & Leases** (Cryptographic single-use launch tickets, configurable `game_base_url`, heartbeat leases, fail-closed verification)
5. **Client Page Telemetry** (Informational route and tab tracking with automatic stale-state detection)
6. **Replay-Protected Protected Actions** (Client idempotency keys, cryptographically signed nonces, atomic balance reservation)
7. **Public WinGo & Lottery Game APIs** (Live countdown, active issue rounds, historical draw results, and payout rules without requiring authentication)

> **Architectural Guarantee:** The backend is 100% server-authoritative. Browser `localStorage`, cookies, frontend routing URLs (e.g., `/game`), or client-reported states are **never** treated as proof of authentication or game activity.

---

## Deployments & Runtimes

The platform is available in two parallel production-grade runtimes sharing identical API specifications and database schemas:

| Runtime | Technology | Database | Deployment Command | Live Host |
|---|---|---|---|---|
| **Edge Serverless** | Cloudflare Workers (V8) | Cloudflare D1 (SQLite Edge) | `npx wrangler deploy --config ./cloudflare-worker/wrangler.jsonc` | `https://user-state-api.shakir-ansarii075.workers.dev` |
| **Python Backend** | FastAPI / Python 3.10+ | SQLite / PostgreSQL | `uvicorn app.main:app --port 8000` | `http://localhost:8000` |

---

## Upstream Client Provider Architecture

The gateway is decoupled from any specific upstream client:
- **Upstream Provider**: Configurable via `PROVIDER_API_URL` and `PROVIDER_ORIGIN`. Acts as a live synchronization proxy for existing gaming / lottery backends.
- **Configurable Game Base URL**: Set globally via `GAME_BASE_URL` or overridden on a per-launch basis via request payloads (`body.game_base_url`).
- **Normalized Client Identity**: Uses `external_uid` (with `shreewin_uid` backward-compatibility alias) to track external upstream account identifiers alongside the gateway internal user ID.

---

## Quick Start (Python Local Environment)

### 1. Prerequisites
- Python 3.10+ (tested through Python 3.14)
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

- API Base: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `User State Authorization API` | Application title |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DATABASE_URL` | `sqlite:///./user_state.db` | SQLite (`sqlite:///...`) or PostgreSQL (`postgresql+psycopg://...`) |
| `JWT_SECRET_KEY` | `replace-this-with-a-long-random-secret` | 32+ character entropy secret key |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_MINUTES` | `15` | Expiry duration for JWT access tokens |
| `REFRESH_TOKEN_DAYS` | `30` | Expiry duration for refresh token family |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum required password characters |
| `PAGE_STALE_SECONDS` | `120` | Threshold after which client page telemetry is marked stale |
| `GAME_HEARTBEAT_GRACE_SECONDS`| `90` | Interval allowed between game heartbeats before lease expires |
| `GAME_SESSION_TTL_SECONDS` | `3600` | Maximum absolute lifetime of a game session |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed frontend origins |
| `PROVIDER_API_URL` | `https://api.shreewinapi.com` | Upstream client API gateway URL |
| `PROVIDER_ORIGIN` | `https://shreewin39.com` | Upstream client origin header |
| `GAME_BASE_URL` | `https://h5.ar-lottery01.com` | Default base URL for iframe / H5 game sessions |

---

## WinGo Public Game APIs (No Authentication Required)

These endpoints allow frontends, display screens, and bots to query live WinGo game states, countdowns, and historical results without sending authentication tokens.

### 1. WinGo Game Types (`GET /games/wingo/types` or `POST /wingo/types`)
Returns all active WinGo game modes (30s, 1m, 3m, 5m), time intervals, bet scopes, and multiplier steps.

```http
GET /games/wingo/types
```
**Response (200 OK):**
```json
{
  "success": true,
  "auth_required": false,
  "server_time": "2026-09-08 22:06:01",
  "types": [
    {
      "type_id": 30,
      "type_name": "30 second",
      "interval_minutes": 0.5,
      "game_code": "WinGo_30S",
      "bet_scope": [1, 10, 100, 1000],
      "multipliers": [1, 5, 10, 20, 50, 100]
    },
    {
      "type_id": 1,
      "type_name": "Win 1 minute",
      "interval_minutes": 1.0,
      "game_code": "WinGo_1M",
      "bet_scope": [1, 10, 100, 1000],
      "multipliers": [1, 5, 10, 20, 50, 100]
    }
  ]
}
```

### 2. Live Active Issue & Countdown (`GET /games/wingo/issue?type=1m` or `POST /games/wingo/issue`)
Returns the active round issue number, draw end time, server time, and live remaining countdown in seconds.
*Parameters:* `type` (`30s`, `1m`, `3m`, `5m`) or `type_id` (`30`, `1`, `2`, `3`).

```http
GET /games/wingo/issue?type=1m
```
**Response (200 OK):**
```json
{
  "success": true,
  "auth_required": false,
  "type_id": 1,
  "issue_number": "20260908100010997",
  "start_time": "2026-09-08 22:06:00",
  "end_time": "2026-09-08 22:07:00",
  "server_time": "2026-09-08 22:06:01",
  "interval_minutes": 1,
  "countdown_seconds": 59
}
```

### 3. Historical Draw Results (`GET /games/wingo/history?type=1m&size=10` or `POST /games/wingo/history`)
Returns past winning rounds parsed and enriched with numbers (`0-9`), colors (`green`, `red`, `violet`), size (`big`/`small`), and premium.

```http
GET /games/wingo/history?type=1m&size=5
```
**Response (200 OK):**
```json
{
  "success": true,
  "auth_required": false,
  "type_id": 1,
  "page_no": 1,
  "total_page": 144,
  "total_count": 1440,
  "results": [
    {
      "issue_number": "20260908100010996",
      "number": 1,
      "colours": ["green"],
      "size": "small",
      "premium": 1
    }
  ]
}
```

### 4. Recent Winning Numbers (`GET /games/wingo/recent-results?type=1m`)
Returns the sequence of the last 5 winning numbers (e.g. `[3, 7, 5, 5, 5]`).

### 5. WinGo Rules & Multipliers (`GET /games/wingo/rules?type=1m`)
Returns game presentation HTML and payout odds multipliers.

### 6. TRX WinGo Types (`GET /games/wingo/trx/types`)
Returns TRX WinGo lottery modes and intervals.

---

## State Authorization & Game Lifecycle

### 1. User Login & Upstream Sync (`POST /auth/login`)
Validates credentials, retrieves `external_uid`, registers the session, and returns tokens.

```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "7666783464",
  "password": "yourPassword",
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
  "external_uid": 229059,
  "expires_at": "2026-09-08T15:44:11Z"
}
```

### 2. Launch Game with Configurable URL (`POST /games/launch`)
Issues a cryptographic single-use ticket and generates the game launch URL.

```http
POST /games/launch
Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json

{
  "game_id": "wingo-1m",
  "vendor": "internal",
  "game_base_url": "https://h5.ar-lottery01.com"
}
```
**Response (200 OK):**
```json
{
  "game_session_id": "d8e3fa02187b4582",
  "state": "PENDING",
  "expires_at": "2026-09-08T16:29:11Z",
  "launch_ticket": "Kj89w_20xLk...",
  "ticket_expires_at": "2026-09-08T15:31:11Z",
  "launch_url": "https://h5.ar-lottery01.com/?game_id=wingo-1m&session_id=d8e3fa02187b4582&ticket=Kj89w_20xLk..."
}
```

### 3. Consume Ticket & Activate Game Session (`POST /games/tickets/consume`)
Validates the ticket atomically, transitions session from `PENDING` to `ACTIVE`, and invalidates the ticket.

### 4. Authoritative State Overview (`GET /system/user-state`)
Evaluates all 4 authoritative conditions simultaneously:
1. Authenticated session exists and is active
2. Available balance breakdown (`cash`, `bonus`, `locked`)
3. Inside an active game session with valid heartbeat lease
4. Client route telemetry status

---

## All Endpoints Reference

| Method | Path | Auth Required | Description |
|---|---|:---:|---|
| `GET` | `/healthz` | No | Service health status and provider configuration |
| `GET` / `POST` | `/games/wingo/types` | No | List WinGo game types and time intervals |
| `GET` / `POST` | `/games/wingo/issue` | No | Active round issue number and live countdown |
| `GET` / `POST` | `/games/wingo/history` | No | Historical round results with numbers, colors, and sizes |
| `GET` / `POST` | `/games/wingo/recent-results` | No | Last 5 winning numbers sequence |
| `GET` / `POST` | `/games/wingo/rules` | No | WinGo payout rules and odds presentation |
| `GET` / `POST` | `/games/wingo/trx/types` | No | TRX WinGo game types |
| `POST` | `/auth/register` | No | Register new account with identifier, password, invite code |
| `POST` | `/auth/login` | No | Authenticate user, sync external identity, issue tokens |
| `POST` | `/auth/refresh` | No | Rotate refresh tokens; revokes family if reuse attack detected |
| `POST` | `/auth/logout` | Yes | Revoke server session, refresh family, and all game leases |
| `GET` | `/me` | Yes | Validate active session and identity details (`external_uid`) |
| `GET` | `/wallet/available-balance` | Yes | Fresh balance breakdown (`cash`, `bonus`, `locked`) |
| `POST` | `/telemetry/page-view` | Yes | Record frontend route telemetry |
| `POST` | `/games/launch` | Yes | Create game session, ticket, and configurable launch URL |
| `POST` | `/games/tickets/consume` | Yes | Consume launch ticket and activate game session lease |
| `POST` | `/games/{id}/heartbeat` | Yes | Renew heartbeat lease for an active game session |
| `POST` | `/games/{id}/exit` | Yes | Close game session cleanly |
| `POST` | `/games/{id}/settle` | Yes | Settle game round and credit payout |
| `GET` | `/system/user-state` | Yes | Full 4-condition authoritative state evaluation |
| `POST` | `/authorize-action` | Yes | Evaluate authorization & issue action nonce |
| `POST` | `/game-sessions/{id}/actions/{op}` | Yes | Atomic protected action execution & idempotent debit |

---

## Running Automated Tests

The test suite covers full lifecycle validation, refresh-token rotation, reuse detection, heartbeat expiration, multithreaded double-spend concurrency prevention, and public unauthenticated WinGo endpoints:

```powershell
.\.venv\Scripts\pytest.exe -v
```

All 12 automated test cases pass with 100% success.
