# WinGate Platform — Architecture & State Authorization Improvement Plan

## Purpose

This document details the architecture and roadmap for the User State Authorization Platform. The platform provides server-authoritative state validation across four core conditions:

1. **Identity & Authentication**: The user is verified (locally or synced with a configurable upstream provider/client).
2. **Authoritative Balance**: The user has sufficient available balance across their cash, bonus, and locked funds.
3. **Active Game Session Lease**: The user is actively inside an authorized game session with verified heartbeats.
4. **Action Authorization & Idempotency**: High-value protected operations (bets, transfers, state mutations) are atomically authorized and executed once with cryptographically signed nonces.

---

## 1. Multi-Client & Upstream Provider Architecture

The gateway is built to operate either **standalone** (direct edge database via Cloudflare D1 / PostgreSQL) or as an **authoritative proxy gateway** fronting upstream gaming or lottery client systems:

- **Configurable Provider Endpoints**: Configured via environment variables (`PROVIDER_API_URL`, `PROVIDER_ORIGIN`) and per-request overrides.
- **Generic User & Token Mapping**: Uses `external_uid`, `upstream_token`, and `provider_session_url` as primary contract keys, while retaining legacy backward-compatibility aliases (`shreewin_uid`, `lottery_login_url`) where needed.
- **Dynamic Game Base URLs**: Game launch URLs (`game_base_url`) can be specified per launch request or default to the platform environment configuration.

---

## 2. Priority Overview

| Priority | Area | Current State | Target Design |
|---|---|---|---|
| P0 | Refresh token rotation | Rotated refresh tokens are tracked with family IDs and reuse detection | Return rotated refresh tokens and immediately revoke families on reuse anomaly |
| P0 | Protected action | Action nonces and authorization receipts are created atomically | Bind authorization to operations and consume nonces with idempotency records |
| P0 | Balance transaction | Pre-flight balance checks combined with balance version locking | Perform balance verification and reservation/debit in a single atomic transaction |
| P0 | Launch ticket | Cryptographic one-time launch tickets with expiration | Ticket hash is bound to user, session, and game; single-use consumption |
| P1 | Game-session lifecycle | Lease model with configurable TTL and heartbeat grace period | Lifecycle transitions: `PENDING` -> `ACTIVE` -> `CLOSED` / `EXPIRED` |
| P1 | Session/device binding | Session IDs and device IDs bound to access tokens | Strict verification of device identifiers on sensitive state mutations |

---

## 3. Endpoints Overview

- `GET /healthz`: Health status and provider configuration.
- `POST /auth/register`: Local user registration.
- `POST /auth/login`: Authentication with optional live upstream client synchronization.
- `POST /auth/refresh`: Refresh token rotation.
- `POST /auth/logout`: Revoke active session.
- `GET /me`: Authenticated user profile and session data.
- `GET /wallet/available-balance`: Authoritative wallet balance calculation.
- `POST /page-state`: Client route/navigation tracking.
- `POST /games/launch`: Single-use game launch ticket generation with configurable game base URL.
- `POST /games/consume-ticket`: Single-use ticket redemption to activate game session.
- `POST /games/{id}/heartbeat`: Game session lease renewal.
- `POST /games/{id}/exit`: Graceful game session close.
- `GET /system/user-state`: Comprehensive 4-condition state evaluation.
- `POST /actions/authorize`: Cryptographic pre-authorization receipt generation.
- `POST /actions/execute`: Idempotent action execution with balance debit and audit logging.
