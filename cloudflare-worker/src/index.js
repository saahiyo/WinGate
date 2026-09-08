// Cloudflare Worker: User State Authorization API
// Server-authoritative Identity, Wallet Balance, Game Session Lease, and Action Authorization

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Device-Id, Idempotency-Key',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    const json = (data, status = 200) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    };

    const err = (status, code, message, extra = null) => {
      const trace_id = randomHex(16);
      const detail = { code, message, trace_id, ...(extra || {}) };
      return json({ detail }, status);
    };

    const nowIso = () => new Date().toISOString();
    const nowSec = () => Math.floor(Date.now() / 1000);

    const minPasswordLength = parseInt(env.MIN_PASSWORD_LENGTH || '8', 10);
    const jwtSecret = env.JWT_SECRET_KEY || 'default-secret-key-cloudflare-2026';
    const pageStaleSec = parseInt(env.PAGE_STALE_SECONDS || '120', 10);
    const heartbeatGraceSec = parseInt(env.GAME_HEARTBEAT_GRACE_SECONDS || '90', 10);

    // Auth Middleware Helper
    async function requireContext() {
      const authHeader = request.headers.get('Authorization') || '';
      if (!authHeader.startsWith('Bearer ')) {
        return { error: err(401, 'AUTH_REQUIRED', 'Missing or invalid bearer token') };
      }
      const token = authHeader.slice(7).trim();
      const payload = await verifyJwt(token, jwtSecret);
      if (!payload || !payload.sub || !payload.sid) {
        return { error: err(401, 'AUTH_REQUIRED', 'Invalid or expired access token') };
      }

      const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(Number(payload.sub)).first();
      if (!user) {
        return { error: err(401, 'AUTH_REQUIRED', 'User not found') };
      }
      if (user.status !== 'active') {
        return { error: err(403, 'ACCOUNT_DISABLED', 'Account is disabled') };
      }

      const sess = await env.DB.prepare('SELECT * FROM auth_sessions WHERE id = ?').bind(payload.sid).first();
      if (!sess || sess.revoked_at || new Date(sess.expires_at).getTime() <= Date.now()) {
        return { error: err(401, 'AUTH_REVOKED', 'Session is revoked or expired') };
      }

      // Update session last_seen_at
      await env.DB.prepare('UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?')
        .bind(nowIso(), sess.id).run();

      return { user, sess };
    }

    try {
      // ----------------------------------------------------
      // 1. Health Check
      // ----------------------------------------------------
      if (method === 'GET' && path === '/healthz') {
        return json({ status: 'ok', environment: env.ENVIRONMENT || 'production' });
      }

      // ----------------------------------------------------
      // 2. Register
      // ----------------------------------------------------
      if (method === 'POST' && path === '/auth/register') {
        const body = await request.json().catch(() => ({}));
        const identifier = (body.identifier || '').trim().toLowerCase();
        const password = body.password || '';
        const invite_code = (body.invite_code || '').trim() || null;

        if (!identifier || identifier.length < 3) {
          return err(422, 'VALIDATION_ERROR', 'Identifier must be at least 3 characters');
        }
        if (password.length < minPasswordLength) {
          return err(422, 'WEAK_PASSWORD', `Password must contain at least ${minPasswordLength} characters`);
        }

        const existing = await env.DB.prepare('SELECT id FROM users WHERE identifier = ?').bind(identifier).first();
        if (existing) {
          return err(409, 'USER_EXISTS', 'An account already exists');
        }

        const hashed = await hashPassword(password);
        const regAt = nowIso();

        const insertUser = await env.DB.prepare(
          'INSERT INTO users (identifier, password_hash, salt, invite_code, status, registered_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(identifier, hashed, '', invite_code, 'active', regAt).run();

        const userId = insertUser.meta.last_row_id;

        // Initialize balance & audit
        await env.DB.batch([
          env.DB.prepare('INSERT INTO balances (user_id, cash_available, bonus_available, locked_amount, version, updated_at) VALUES (?, 0.0, 0.0, 0.0, 1, ?)')
            .bind(userId, regAt),
          env.DB.prepare('INSERT INTO audit_events (event, user_id, created_at, metadata_json) VALUES (?, ?, ?, ?)')
            .bind('USER_REGISTERED', userId, regAt, JSON.stringify({ source: 'cloudflare_api', invite_code }))
        ]);

        return json({
          user_id: userId,
          registered: true,
          registered_at: regAt,
          invite_code: invite_code,
        }, 201);
      }

      // ----------------------------------------------------
      // 3. Login
      // ----------------------------------------------------
      if (method === 'POST' && path === '/auth/login') {
        const body = await request.json().catch(() => ({}));
        const identifier = (body.identifier || '').trim().toLowerCase();
        const password = body.password || '';
        const device_id = body.device_id || null;

        const user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ?').bind(identifier).first();
        if (!user || !(await verifyPassword(password, user.password_hash))) {
          return err(401, 'AUTH_REQUIRED', 'Invalid credentials');
        }
        if (user.status !== 'active') {
          return err(403, 'ACCOUNT_DISABLED', 'Account is disabled or inactive');
        }

        const sid = randomHex(16);
        const family_id = randomHex(16);
        const refresh = randomToken(36);
        const refresh_hash = await sha256Hex(refresh);

        const now = new Date();
        const nowStr = now.toISOString();
        const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO auth_sessions (id, user_id, refresh_hash, refresh_family_id, refresh_token_version, device_id, expires_at, last_seen_at)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
          `).bind(sid, user.id, refresh_hash, family_id, device_id, expiresAt, nowStr),

          env.DB.prepare(`
            INSERT INTO refresh_token_records (token_hash, family_id, auth_session_id, user_id, version, is_used, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
          `).bind(refresh_hash, family_id, sid, user.id, nowStr),

          env.DB.prepare(`
            INSERT INTO audit_events (event, user_id, session_id, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?)
          `).bind('USER_LOGGED_IN', user.id, sid, nowStr, JSON.stringify({ device_id }))
        ]);

        const accessToken = await createJwt({
          sub: String(user.id),
          sid: sid,
          iat: nowSec(),
          exp: nowSec() + 15 * 60,
          typ: 'access',
        }, jwtSecret);

        return json({
          access_token: accessToken,
          token_type: 'bearer',
          refresh_token: refresh,
          session_id: sid,
          user_id: user.id,
          expires_at: new Date(now.getTime() + 15 * 60 * 1000).toISOString(),
        });
      }

      // ----------------------------------------------------
      // 4. Refresh Token Rotation
      // ----------------------------------------------------
      if (method === 'POST' && path === '/auth/refresh') {
        const body = await request.json().catch(() => ({}));
        const rawRefresh = body.refresh_token || '';
        if (!rawRefresh) return err(422, 'VALIDATION_ERROR', 'Missing refresh_token');

        const tokenHash = await sha256Hex(rawRefresh);
        const tokenRec = await env.DB.prepare('SELECT * FROM refresh_token_records WHERE token_hash = ?').bind(tokenHash).first();
        if (!tokenRec) return err(401, 'AUTH_REVOKED', 'Invalid refresh token');

        const now = new Date();
        const nowStr = now.toISOString();

        if (tokenRec.is_used) {
          // Token reuse detected! Revoke entire family
          await env.DB.batch([
            env.DB.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE refresh_family_id = ?').bind(nowStr, tokenRec.family_id),
            env.DB.prepare('INSERT INTO audit_events (event, user_id, created_at, metadata_json) VALUES (?, ?, ?, ?)')
              .bind('REFRESH_TOKEN_REUSE_DETECTED', tokenRec.user_id, nowStr, JSON.stringify({ family_id: tokenRec.family_id }))
          ]);
          return err(401, 'AUTH_REVOKED', 'Refresh token reuse detected; all sessions revoked');
        }

        const sess = await env.DB.prepare('SELECT * FROM auth_sessions WHERE id = ?').bind(tokenRec.auth_session_id).first();
        if (!sess || sess.revoked_at || new Date(sess.expires_at).getTime() <= now.getTime()) {
          return err(401, 'AUTH_REVOKED', 'Session is invalid or expired');
        }

        const newRefresh = randomToken(36);
        const newHash = await sha256Hex(newRefresh);
        const newVersion = tokenRec.version + 1;

        await env.DB.batch([
          env.DB.prepare('UPDATE refresh_token_records SET is_used = 1, used_at = ? WHERE id = ?').bind(nowStr, tokenRec.id),
          env.DB.prepare('UPDATE auth_sessions SET refresh_hash = ?, refresh_token_version = ?, refresh_rotated_at = ? WHERE id = ?')
            .bind(newHash, newVersion, nowStr, sess.id),
          env.DB.prepare(`
            INSERT INTO refresh_token_records (token_hash, family_id, auth_session_id, user_id, version, is_used, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
          `).bind(newHash, tokenRec.family_id, sess.id, sess.user_id, newVersion, nowStr)
        ]);

        const newAccessToken = await createJwt({
          sub: String(sess.user_id),
          sid: sess.id,
          iat: nowSec(),
          exp: nowSec() + 15 * 60,
          typ: 'access',
        }, jwtSecret);

        return json({
          access_token: newAccessToken,
          refresh_token: newRefresh,
          token_type: 'bearer',
        });
      }

      // ----------------------------------------------------
      // 5. Logout
      // ----------------------------------------------------
      if (method === 'POST' && path === '/auth/logout') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;
        const nowStr = nowIso();

        await env.DB.batch([
          env.DB.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE id = ?').bind(nowStr, sess.id),
          env.DB.prepare('UPDATE game_sessions SET state = "CLOSED", closed_at = ?, close_reason = "LOGOUT" WHERE user_id = ? AND auth_session_id = ? AND state = "ACTIVE"')
            .bind(nowStr, user.id, sess.id),
          env.DB.prepare('INSERT INTO audit_events (event, user_id, session_id, created_at) VALUES (?, ?, ?, ?)')
            .bind('USER_LOGGED_OUT', user.id, sess.id, nowStr)
        ]);

        return json({ logged_out: true });
      }

      // ----------------------------------------------------
      // 6. Identity / Session Info (/me)
      // ----------------------------------------------------
      if (method === 'GET' && path === '/me') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;

        return json({
          authenticated: true,
          user_id: user.id,
          session_id: sess.id,
          invite_code: user.invite_code,
          registered_at: user.registered_at,
          session_expires_at: sess.expires_at,
          last_seen_at: sess.last_seen_at,
        });
      }

      // ----------------------------------------------------
      // 7. Wallet Balance
      // ----------------------------------------------------
      if (method === 'GET' && path === '/wallet/available-balance') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user } = ctx;

        const b = await env.DB.prepare('SELECT * FROM balances WHERE user_id = ?').bind(user.id).first();
        const cash = b ? Number(b.cash_available) : 0;
        const bonus = b ? Number(b.bonus_available) : 0;
        const locked = b ? Number(b.locked_amount) : 0;
        const available = Math.max(0, cash - locked);

        return json({
          user_id: user.id,
          cash_available: cash,
          bonus_available: bonus,
          locked_amount: locked,
          available_for_game: available,
          balance_version: b ? b.version : 1,
          as_of: b ? b.updated_at : nowIso(),
        });
      }

      // ----------------------------------------------------
      // 8. Page Telemetry
      // ----------------------------------------------------
      if (method === 'POST' && path === '/telemetry/page-view') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;

        const body = await request.json().catch(() => ({}));
        const route = body.route || '/';
        const page_name = body.page_name || null;
        const tab_id = body.tab_id || null;
        const nowStr = nowIso();

        await env.DB.prepare(`
          INSERT INTO page_states (user_id, session_id, tab_id, route, page_name, last_seen_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(user.id, sess.id, tab_id, route, page_name, nowStr).run();

        return json({ recorded: true, last_seen_at: nowStr });
      }

      // ----------------------------------------------------
      // 9. Launch Game
      // ----------------------------------------------------
      if (method === 'POST' && path === '/games/launch') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;

        const body = await request.json().catch(() => ({}));
        const game_id = body.game_id;
        const vendor = body.vendor || 'internal';
        if (!game_id) return err(422, 'VALIDATION_ERROR', 'game_id is required');

        const now = new Date();
        const nowStr = now.toISOString();
        const ticketExpires = new Date(now.getTime() + 120 * 1000).toISOString();
        const gameExpires = new Date(now.getTime() + 3600 * 1000).toISOString();

        const launchTicket = randomToken(32);
        const ticketHash = await sha256Hex(launchTicket);
        const ticketId = randomHex(16);
        const gameSessionId = randomHex(16);

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO game_sessions (id, user_id, auth_session_id, game_id, vendor, state, created_at, expires_at, last_heartbeat_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
          `).bind(gameSessionId, user.id, sess.id, game_id, vendor, nowStr, gameExpires, nowStr),

          env.DB.prepare(`
            INSERT INTO game_launch_tickets (id, user_id, auth_session_id, game_id, ticket_hash, is_consumed, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
          `).bind(ticketId, user.id, sess.id, game_id, ticketHash, ticketExpires, nowStr),

          env.DB.prepare(`
            INSERT INTO audit_events (event, user_id, session_id, game_session_id, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind('GAME_LAUNCH_INITIATED', user.id, sess.id, gameSessionId, nowStr, JSON.stringify({ game_id, vendor }))
        ]);

        return json({
          game_session_id: gameSessionId,
          state: 'PENDING',
          expires_at: gameExpires,
          launch_ticket: launchTicket,
          ticket_expires_at: ticketExpires,
        });
      }

      // ----------------------------------------------------
      // 10. Consume Game Launch Ticket
      // ----------------------------------------------------
      if (method === 'POST' && path === '/games/tickets/consume') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;

        const body = await request.json().catch(() => ({}));
        const rawTicket = body.launch_ticket;
        const gameSessionId = body.game_session_id;
        if (!rawTicket || !gameSessionId) return err(422, 'VALIDATION_ERROR', 'launch_ticket and game_session_id required');

        const ticketHash = await sha256Hex(rawTicket);
        const ticketRec = await env.DB.prepare('SELECT * FROM game_launch_tickets WHERE ticket_hash = ?').bind(ticketHash).first();
        if (!ticketRec || ticketRec.is_consumed || new Date(ticketRec.expires_at).getTime() <= Date.now()) {
          return err(401, 'TICKET_INVALID', 'Launch ticket is invalid or expired');
        }

        const gs = await env.DB.prepare('SELECT * FROM game_sessions WHERE id = ?').bind(gameSessionId).first();
        if (!gs || gs.user_id !== user.id || gs.auth_session_id !== sess.id) {
          return err(403, 'GAME_SESSION_MISMATCH', 'Session does not match ticket');
        }

        const nowStr = nowIso();
        await env.DB.batch([
          env.DB.prepare('UPDATE game_launch_tickets SET is_consumed = 1, consumed_at = ? WHERE id = ?').bind(nowStr, ticketRec.id),
          env.DB.prepare('UPDATE game_sessions SET state = "ACTIVE", last_heartbeat_at = ? WHERE id = ?').bind(nowStr, gs.id),
          env.DB.prepare('INSERT INTO audit_events (event, user_id, session_id, game_session_id, created_at) VALUES (?, ?, ?, ?, ?)')
            .bind('GAME_SESSION_ACTIVATED', user.id, sess.id, gs.id, nowStr)
        ]);

        return json({
          consumed: true,
          game_session_id: gs.id,
          state: 'ACTIVE',
        });
      }

      // ----------------------------------------------------
      // 11. Heartbeat
      // ----------------------------------------------------
      const heartbeatMatch = path.match(/^\/games\/([a-zA-Z0-9_-]+)\/heartbeat$/);
      if (method === 'POST' && heartbeatMatch) {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;
        const gameSessionId = heartbeatMatch[1];

        const gs = await env.DB.prepare('SELECT * FROM game_sessions WHERE id = ?').bind(gameSessionId).first();
        if (!gs || gs.user_id !== user.id || gs.auth_session_id !== sess.id || gs.state !== 'ACTIVE') {
          return err(404, 'GAME_SESSION_NOT_FOUND', 'Active game session not found');
        }

        const nowStr = nowIso();
        await env.DB.prepare('UPDATE game_sessions SET last_heartbeat_at = ? WHERE id = ?').bind(nowStr, gs.id).run();

        return json({ renewed: true, game_session_id: gs.id, heartbeat_at: nowStr });
      }

      // ----------------------------------------------------
      // 12. Combined Authoritative Status (/system/user-state)
      // ----------------------------------------------------
      if (method === 'GET' && path === '/system/user-state') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess } = ctx;

        const now = Date.now();
        const p = await env.DB.prepare('SELECT * FROM page_states WHERE user_id = ? AND session_id = ? ORDER BY last_seen_at DESC LIMIT 1')
          .bind(user.id, sess.id).first();

        const b = await env.DB.prepare('SELECT * FROM balances WHERE user_id = ?').bind(user.id).first();

        const gs = await env.DB.prepare('SELECT * FROM game_sessions WHERE user_id = ? AND auth_session_id = ? AND state = "ACTIVE" ORDER BY created_at DESC LIMIT 1')
          .bind(user.id, sess.id).first();

        const freshPage = Boolean(p && (now - new Date(p.last_seen_at).getTime()) <= pageStaleSec * 1000);
        const activeGame = Boolean(
          gs &&
          new Date(gs.expires_at).getTime() > now &&
          (now - new Date(gs.last_heartbeat_at).getTime()) <= heartbeatGraceSec * 1000
        );

        const cash = b ? Number(b.cash_available) : 0;
        const bonus = b ? Number(b.bonus_available) : 0;
        const locked = b ? Number(b.locked_amount) : 0;
        const available = Math.max(0, cash - locked);

        return json({
          user: {
            id: user.id,
            registered: true,
            invite_code: user.invite_code,
            registered_at: user.registered_at,
          },
          authentication: {
            logged_in: true,
            session_id: sess.id,
            last_seen_at: sess.last_seen_at,
            expires_at: sess.expires_at,
          },
          page: {
            route: p ? p.route : null,
            page_name: p ? p.page_name : null,
            last_reported_at: p ? p.last_seen_at : null,
            is_stale: !freshPage,
          },
          game: {
            inside_game: activeGame,
            game_session_id: activeGame ? gs.id : null,
            state: activeGame ? gs.state : null,
          },
          balance: {
            cash_available: cash,
            bonus_available: bonus,
            locked_amount: locked,
            available_for_game: available,
            balance_version: b ? b.version : 1,
            as_of: b ? b.updated_at : nowIso(),
          },
        });
      }

      // Default Not Found
      return err(404, 'NOT_FOUND', `Endpoint not found: ${method} ${path}`);
    } catch (e) {
      return err(500, 'INTERNAL_ERROR', e.message || 'Server error');
    }
  }
};

// ---------------------------------------------------------
// Cryptography Utilities (Native Web Crypto API)
// ---------------------------------------------------------
async function hashPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: saltBytes,
    iterations: 100000,
    hash: 'SHA-256'
  }, keyMaterial, 256);
  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}$${hashHex}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes('$')) return false;
  const [saltHex, origHash] = stored.split('$');
  const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: saltBytes,
    iterations: 100000,
    hash: 'SHA-256'
  }, keyMaterial, 256);
  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === origHash;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function createJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const hEnc = base64UrlEncode(JSON.stringify(header));
  const pEnc = base64UrlEncode(JSON.stringify(payload));
  const data = `${hEnc}.${pEnc}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sEnc = Array.from(new Uint8Array(sig)).map(b => String.fromCharCode(b)).join('');
  return `${data}.${base64UrlEncode(sEnc)}`;
}

async function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [hEnc, pEnc, sEnc] = parts;
  const data = `${hEnc}.${pEnc}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sigStr = base64UrlDecode(sEnc);
  const sigBytes = new Uint8Array(sigStr.split('').map(c => c.charCodeAt(0)));
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
  if (!valid) return null;
  const payload = JSON.parse(base64UrlDecode(pEnc));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

function randomHex(len = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(len = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return base64UrlEncode(Array.from(bytes).map(b => String.fromCharCode(b)).join(''));
}
