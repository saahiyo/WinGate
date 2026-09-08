# ShreeWin State Authorization Project — Improvement Plan

## Purpose

This document lists the changes required to turn the current authentication, balance, game-session, and action-authorization prototype into a stronger production-ready design.

The recommendations below are based on the inspected project implementation and the accompanying state-validation report. They focus on the four required conditions:

1. The user is authenticated.
2. The user has sufficient available balance.
3. The user is actually inside an active game session.
4. The protected action is authorized and cannot be replayed or raced.

---

# 1. Priority Overview

| Priority | Area | Current State | Required Improvement |
|---|---|---|---|
| P0 | Refresh token rotation | New refresh token is generated but not returned | Return the rotated refresh token and implement proper reuse detection |
| P0 | Protected action | Authorization decision is created but not consumed | Bind authorization to a real protected operation and consume it atomically |
| P0 | Balance transaction | Balance can be checked separately from debit/reservation | Perform final balance check and reservation/debit in one transaction |
| P0 | Launch ticket | Random ticket is returned but not persisted | Persist a hash, bind it to the user/session/game, expire it, and consume it once |
| P1 | Game-session lifecycle | Good prototype lease model | Tie game launch, provider acknowledgement, heartbeat, exit, and settlement together |
| P1 | Session/device binding | Session IDs exist | Enforce binding consistently for protected actions |
| P1 | Idempotency | Mentioned but incomplete | Add idempotency keys to all state-changing operations |
| P1 | Fail-closed behavior | Partially specified | Ensure dependency failures cannot accidentally authorize an action |
| P1 | Auditability | Basic model exists | Add immutable security/action audit records |
| P2 | Page state | User-level state can be overwritten by another tab/session | Keep telemetry separate from security state and track by session/tab where useful |
| P2 | Error model | Error taxonomy exists | Apply it consistently across endpoints |
| P2 | Testing | Prototype tests exist / expected tests are described | Add deterministic integration and concurrency tests |

---

# 2. P0 — Fix Refresh Token Rotation

## Current problem

The refresh endpoint generates a new refresh token and stores its hash, but the newly generated plaintext token is not returned to the client.

Current logic is effectively:

```python
sess.refresh_hash = hash_secret(secrets.token_urlsafe(48))
db.commit()

return {
    "access_token": new_access_token,
    "token_type": "bearer",
}
```

After rotation:

```text
Client still owns old refresh token
              ↓
Server now stores hash of NEW token
              ↓
Next refresh with old token fails
```

## Required implementation

Generate the new token once, hash that exact value, persist the hash, then return the plaintext token exactly once.

```python
new_refresh = secrets.token_urlsafe(48)

sess.refresh_hash = hash_secret(new_refresh)
sess.refresh_rotated_at = utcnow()

db.commit()

return {
    "access_token": create_access_token(user.id, sess.id),
    "refresh_token": new_refresh,
    "token_type": "bearer",
}
```

## Recommended hardening

Add refresh-token family tracking:

```text
refresh_family_id
refresh_token_version
rotated_at
revoked_at
```

Detect reuse:

```text
Old refresh token used after rotation
                ↓
        reuse detected
                ↓
revoke entire refresh-token family
                ↓
require fresh login
```

This protects against stolen refresh tokens.

---

# 3. P0 — Turn `authorize-action` Into a Real Authorization Capability

## Current problem

The project creates an `ActionNonce` and returns an allowed decision, but the decision is not subsequently consumed by the protected operation.

The database has a `consumed_at` field, but the authorization lifecycle is incomplete.

Current conceptual flow:

```text
authorize-action
       ↓
allowed = true
       ↓
nothing consumes the authorization
```

## Required flow

Use:

```text
authorization request
        ↓
fresh checks
        ↓
create single-use capability
        ↓
client receives capability ID/token
        ↓
protected action submits capability
        ↓
server atomically consumes capability
        ↓
perform operation
```

The capability should contain or reference:

```text
user_id
auth_session_id
game_session_id
operation
required_balance
balance_version
nonce
created_at
expires_at
consumed_at
```

## Important

The authorization must be:

- short-lived
- tied to one user
- tied to one authentication session
- tied to one game session
- tied to one operation
- single-use
- consumed atomically

Do not treat `allowed=true` as a permanent permission.

---

# 4. P0 — Combine Balance Check With Reservation/Debit

## Current problem

The project can check the balance but does not yet perform the actual monetary reservation/debit in the same transaction.

A vulnerable sequence would be:

```text
Request A → balance = 100 → allowed
Request B → balance = 100 → allowed
Request A → debit
Request B → debit
```

This creates a race condition.

## Required transaction

For a monetary action:

```text
BEGIN TRANSACTION

lock authoritative balance/account row

read fresh available balance

verify:
    account is active
    user is authorized
    game session is active
    heartbeat is fresh
    operation is valid
    nonce is unused
    balance >= required amount

reserve/debit balance

record action

mark capability/nonce consumed

COMMIT
```

If any condition fails:

```text
ROLLBACK
```

## Suggested balance model

Keep distinct values:

```text
cash_available
bonus_available
locked_amount
pending_withdrawal_hold
available_for_game
balance_version
```

Avoid using one display value as the spendable amount.

---

# 5. P0 — Persist and Bind Game Launch Tickets

## Current problem

The launch response generates a random `launch_ticket`, but the ticket must be persisted and validated by the backend to become a security control.

A random string by itself is not enough.

## Required table/model

Example:

```text
GameLaunchTicket
-------------------------
id
ticket_hash
user_id
auth_session_id
game_session_id
game_id
vendor
created_at
expires_at
consumed_at
```

Store only the hash where practical.

## Validation

At consumption time:

```text
ticket exists
AND user matches
AND auth session matches
AND game session matches
AND game matches
AND ticket not expired
AND ticket not consumed
```

Then atomically set:

```text
consumed_at = now
```

The ticket must not be reusable.

---

# 6. P1 — Make Game Session Lifecycle Explicit

The current state-machine direction is correct. Formalize it.

Recommended states:

```text
PENDING
ACTIVE
PAUSED
EXPIRED
EXITED
SETTLEMENT_PENDING
SETTLED
REVOKED
```

Recommended transitions:

```text
PENDING
   ↓ provider acknowledgement
ACTIVE
   ↓ heartbeat timeout
EXPIRED
   ↓ explicit exit
EXITED
   ↓ settlement
SETTLED
```

Authentication revocation should be able to transition an active game session to:

```text
REVOKED
```

---

# 7. P1 — Enforce "Inside Game" With a Server Lease

Do not determine game membership from:

- URL
- iframe existence
- route
- visible game canvas
- local storage
- a JavaScript boolean

Instead require:

```text
GameSession exists
AND
state = ACTIVE
AND
expires_at > now
AND
last_heartbeat_at is recent
AND
auth_session_id matches
AND
user_id matches
AND
game_id matches
```

Example heartbeat window:

```text
heartbeat interval: configurable
grace period: 30–90 seconds
```

Use provider-side acknowledgement/callbacks where available; client heartbeat alone is weaker.

---

# 8. P1 — Separate Game Entry Authorization From Action Authorization

Do not assume these are the same policy.

### Game entry

```text
Can the user launch this game?
```

### Action

```text
Can the user perform this specific protected operation right now?
```

The current project correctly leaves room for game entry without charging money immediately.

Keep those policies separate:

```text
GAME_LAUNCH_ALLOWED
ACTION_ALLOWED
FUNDS_RESERVED
```

This avoids accidentally blocking legitimate game entry or accidentally authorizing a monetary action.

---

# 9. P1 — Add Strict Device/Session Binding

Protected operations should verify:

```text
authenticated user
+
auth_session_id
+
game_session_id
+
device/session binding
```

A different login session should not be able to reuse another session's active game authorization.

For example:

```text
User U
Session A
Game Session A1

Session B attempts to use Game Session A1
                ↓
        GAME_SESSION_MISMATCH
```

Define the business rule for multiple legitimate devices/tabs explicitly.

---

# 10. P1 — Add Idempotency to State-Changing Requests

Use a client-generated request ID:

```http
Idempotency-Key: <unique-value>
```

Persist:

```text
idempotency_key
user_id
operation
request_hash
result
created_at
```

On retry:

```text
same key + same operation
        ↓
return original result
```

Do not execute the operation twice.

Apply this to:

```text
game launch
money reservation/debit
game exit
settlement
withdrawal-related state changes
other monetary actions
```

---

# 11. P1 — Fail Closed

Critical dependencies must never fail into an authorized state.

Example:

```text
Balance service unavailable
        ↓
DO NOT authorize
        ↓
BALANCE_UNAVAILABLE
```

Likewise:

```text
Game state unavailable
        ↓
DO NOT assume ACTIVE
```

and:

```text
Session store unavailable
        ↓
DO NOT assume session valid
```

Recommended principle:

```text
Unknown = Not authorized
```

for protected actions.

---

# 12. P1 — Make JWT Validation and Server Session Validation Both Mandatory

The current project correctly uses a server-side session in addition to JWT validation.

Keep both:

```text
JWT valid
AND
session exists
AND
session not revoked
AND
session not expired
AND
session belongs to JWT user
AND
user account active
```

JWT expiration alone should not be the only revocation mechanism.

---

# 13. P1 — Protect Logout and Revocation

Logout should:

```text
revoke current auth session
revoke/rotate refresh token family
expire associated game sessions
invalidate active capabilities
```

After logout:

```text
old access token
old game session
old authorization capability
old launch ticket
```

must all fail.

Do not rely on the browser merely deleting local storage.

---

# 14. P1 — Add an Immutable Action Audit Record

For every protected action, record:

```text
action_id
user_id
auth_session_id
game_session_id
operation
request_id
idempotency_key
balance_version
amount
authorization_result
created_at
completed_at
status
failure_reason
```

Never store:

```text
passwords
raw access tokens
raw refresh tokens
unnecessary payment credentials
```

Audit records should be append-only or otherwise protected from accidental modification.

---

# 15. P2 — Keep Page Telemetry Out of Authorization

The existing page-state concept is useful for UI/telemetry but should never determine security.

A user can have:

```text
Tab A → lobby
Tab B → game
Device B → account page
```

A single user-level state can be overwritten by whichever request arrives last.

For telemetry, prefer:

```text
user_id
auth_session_id
tab_id
page
last_seen
```

For security, use the dedicated `GameSession` model.

---

# 16. P2 — Normalize Error Responses

Use a consistent structure such as:

```json
{
  "code": "INSUFFICIENT_BALANCE",
  "message": "Insufficient available balance",
  "trace_id": "..."
}
```

Recommended codes:

```text
AUTH_REQUIRED
AUTH_EXPIRED
AUTH_REVOKED
ACCOUNT_DISABLED
BALANCE_UNAVAILABLE
INSUFFICIENT_BALANCE
GAME_SESSION_REQUIRED
GAME_SESSION_EXPIRED
GAME_SESSION_MISMATCH
LAUNCH_TICKET_EXPIRED
LAUNCH_TICKET_CONSUMED
REQUEST_REPLAYED
IDEMPOTENCY_CONFLICT
POLICY_BLOCKED
SERVICE_UNAVAILABLE
```

Do not expose internal database or dependency details to clients.

---

# 17. P2 — Add Rate Limits

Rate-limit at multiple levels:

```text
login
refresh
heartbeat
game launch
authorization
protected action
```

Especially protect:

```text
login brute-force
refresh-token abuse
nonce probing
launch-ticket guessing
rapid repeated monetary actions
```

The existing environment already exposes an API rate-limit header, so mirror this principle in your own service.

---

# 18. P2 — Secrets and Token Handling

Use:

```text
environment variables
secret manager
secure deployment configuration
```

Never commit:

```text
JWT signing secrets
database passwords
API keys
refresh tokens
test account passwords
```

Prefer HttpOnly/Secure/SameSite cookies for browser sessions where the architecture allows it.

If local storage is used for client state, assume the user can modify it.

---

# 19. Required Tests

The system should have automated tests for all of these cases.

## Authentication

```text
[ ] No token → AUTH_REQUIRED
[ ] Invalid token → AUTH_REQUIRED
[ ] Expired token → AUTH_EXPIRED
[ ] Revoked session → AUTH_REVOKED
[ ] JWT user/session mismatch → reject
[ ] Disabled account → reject
[ ] Logout → old session no longer works
```

## Balance

```text
[ ] Balance below threshold → reject
[ ] Balance exactly at threshold → allow
[ ] Balance above threshold → allow
[ ] Cached client balance modified → ignored
[ ] Balance service unavailable → fail closed
[ ] Balance changes during action → transaction handles it
```

## Game state

```text
[ ] No game session → GAME_SESSION_REQUIRED
[ ] Pending session → reject
[ ] Active session + fresh heartbeat → allow
[ ] Expired heartbeat → reject
[ ] Wrong game ID → reject
[ ] Wrong auth session → reject
[ ] Revoked session → reject
[ ] Exited game → reject
```

## Replay

```text
[ ] Same authorization used twice → second attempt rejected
[ ] Same nonce used twice → second attempt rejected
[ ] Same launch ticket used twice → second attempt rejected
[ ] Same idempotency key → original result returned
```

## Concurrency

Test at least:

```text
[ ] Two simultaneous debits with insufficient combined funds
[ ] Two simultaneous actions using same capability
[ ] Two simultaneous actions with same idempotency key
[ ] Logout racing with protected action
[ ] Heartbeat expiry racing with protected action
```

These tests are especially important because ordinary sequential tests will miss race conditions.

---

# 20. Recommended Endpoint Structure

A clean API could look like:

```text
POST /auth/login
POST /auth/refresh
POST /auth/logout

GET  /me
GET  /wallet/available-balance

POST /games/{gameId}/launch
POST /game-sessions/{id}/heartbeat
POST /game-sessions/{id}/exit

POST /authorize-action
POST /game-sessions/{id}/actions/{operation}
```

The protected action endpoint should be the actual enforcement point.

Do not create a model where:

```text
/authorize-action → allowed=true
```

is enough by itself.

---

# 21. Target End-to-End Flow

The final sequence should be:

```text
LOGIN
  ↓
validate credentials
  ↓
create auth session
  ↓
issue access + rotating refresh token
  ↓
GAME LAUNCH
  ↓
validate account/session/policy
  ↓
create GameSession
  ↓
issue one-time launch ticket
  ↓
provider acknowledgement
  ↓
GameSession = ACTIVE
  ↓
heartbeat lease
  ↓
ACTION REQUEST
  ↓
validate JWT
  ↓
validate server session
  ↓
validate account
  ↓
validate active game session
  ↓
validate heartbeat
  ↓
lock/read authoritative balance
  ↓
validate minimum balance
  ↓
validate nonce/idempotency key
  ↓
reserve/debit in same transaction
  ↓
record action
  ↓
consume authorization/nonce
  ↓
COMMIT
  ↓
provider action / settlement
  ↓
close or update GameSession
```

---

# 22. Definition of Done

The implementation should not be considered complete until all of the following are true:

```text
[ ] Access token is validated on every protected request
[ ] Server-side session can revoke access immediately
[ ] Refresh-token rotation returns the newly rotated token
[ ] Refresh-token reuse detection exists
[ ] Authorizations are short-lived and single-use
[ ] Launch tickets are persisted, bound, expired, and consumed
[ ] Game sessions are explicit server-side records
[ ] Game sessions have heartbeat leases
[ ] Protected actions verify game/session binding
[ ] Balance is read from an authoritative ledger
[ ] Balance is checked inside the final transaction
[ ] Funds are reserved/debited atomically
[ ] Idempotency is implemented
[ ] Replay attempts are rejected
[ ] Dependency failures fail closed
[ ] Logout revokes all relevant state
[ ] Audit records exist for sensitive actions
[ ] Concurrency tests pass
[ ] Security tests pass
[ ] No secrets/tokens are committed or logged
```

---

# 23. Recommended Implementation Order

## Phase 1 — Critical security

1. Fix refresh-token rotation.
2. Implement persistent one-time launch tickets.
3. Implement one-time action capabilities.
4. Implement atomic balance reservation/debit.
5. Implement nonce consumption.
6. Add logout/revocation propagation.

## Phase 2 — Session integrity

7. Formalize GameSession states.
8. Enforce heartbeat leases.
9. Enforce user/session/device/game binding.
10. Add provider acknowledgement and reconciliation.

## Phase 3 — Reliability

11. Add idempotency.
12. Add fail-closed dependency handling.
13. Normalize error responses.
14. Add rate limits.
15. Improve audit logging.

## Phase 4 — Verification

16. Add authentication tests.
17. Add balance tests.
18. Add game-state tests.
19. Add replay tests.
20. Add concurrency/race-condition tests.
21. Run the full integration suite before production deployment.

---

# Final Recommendation

The current project has the correct overall security direction: authentication is backed by a server session, balance is intended to be authoritative, game state is represented separately, and the system is designed around a state machine.

The most urgent work is to close the gap between the **authorization prototype** and the **actual protected operation**.

The critical production boundary should be:

```text
authenticated session
        +
active game lease
        +
fresh authoritative balance
        +
policy validation
        +
single-use nonce/capability
        +
idempotency
        +
atomic reservation/debit
        ↓
      ACTION
```

That is the point where the system should make its final allow/deny decision.

Do not rely on the frontend, URL, local storage, displayed balance, cached `userInfo`, or a previously returned `allowed=true` result as a security boundary.
