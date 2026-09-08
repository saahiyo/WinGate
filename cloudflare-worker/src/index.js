// Cloudflare Worker: User State Authorization API (Authoritative Gateway)
// Server-authoritative Identity, Provider Integration, Dynamic Wallet Sync, Game Leases & Configurable Game URLs

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
    const providerApiUrl = env.PROVIDER_API_URL || env.SHREEWIN_API_URL || 'https://api.shreewinapi.com';
    const providerOrigin = env.PROVIDER_ORIGIN || 'https://shreewin39.com';
    const defaultGameBaseUrl = env.GAME_BASE_URL || 'https://h5.ar-lottery01.com';

    // Sign payload for upstream client provider API
    function signProviderPayload(data) {
      const t = { ...data };
      delete t.signature;
      delete t.timestamp;
      t.language = 1;
      t.random = randomHex(16);
      const sortedKeys = Object.keys(t).sort();
      const cleaned = {};
      for (const k of sortedKeys) {
        const v = t[k];
        if (v !== null && v !== '' && !['signature', 'track', 'xosoBettingData'].includes(k)) {
          cleaned[k] = v === 0 ? 0 : v;
        }
      }
      const rawJson = JSON.stringify(cleaned);
      t.signature = md5(rawJson).toUpperCase().slice(0, 32);
      t.timestamp = Math.floor(Date.now() / 1000);
      return t;
    }

    // Call upstream client provider API
    async function callProviderApi(endpoint, data, token = null) {
      const signed = signProviderPayload(data);
      const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || '103.44.118.79';
      const headers = {
        'User-Agent': request.headers.get('user-agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': providerOrigin,
        'Referer': providerOrigin.endsWith('/') ? providerOrigin : `${providerOrigin}/`,
        'Content-Type': 'application/json',
        'AR-REAL-IP': clientIp,
        'X-Real-IP': clientIp,
        'X-Forwarded-For': clientIp,
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      const resp = await fetch(`${providerApiUrl}${endpoint}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(signed),
      });
      return await resp.json().catch(() => ({}));
    }

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

      await env.DB.prepare('UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?')
        .bind(nowIso(), sess.id).run();

      return { user, sess, payload };
    }

    try {
      // ----------------------------------------------------
      // 1. Health Check
      // ----------------------------------------------------
      if (method === 'GET' && path === '/healthz') {
        return json({
          status: 'ok',
          environment: env.ENVIRONMENT || 'production',
          provider_api_url: providerApiUrl,
          game_base_url: defaultGameBaseUrl,
        });
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
      // 3. Login (with Upstream Client Provider Sync & Proxy)
      // ----------------------------------------------------
      if (method === 'POST' && path === '/auth/login') {
        const body = await request.json().catch(() => ({}));
        const identifier = (body.identifier || '').trim();
        const password = body.password || '';
        const device_id = body.device_id || 'mobile-device';

        // Format identifier for upstream provider if numeric phone
        const digitsOnly = identifier.replace(/\D/g, '');
        const phoneFormatted = digitsOnly.length === 10 ? `91${digitsOnly}` : digitsOnly;

        let providerUser = null;
        let providerWallets = null;
        let totalBalance = 0.0;

        let lastProvError = null;
        let provResp = null;

        // Try upstream provider authentication
        try {
          provResp = await callProviderApi('/api/webapi/Login', {
            username: phoneFormatted || identifier,
            pwd: password,
            logintype: 'mobile',
            phonetype: 'Android',
            deviceId: randomHex(16),
          });

          if (provResp && provResp.code === 0 && provResp.data) {
            providerUser = provResp.data;
            // Fetch live wallet balances across all provider games
            const walletResp = await callProviderApi('/api/webapi/GetAllwallets', {}, providerUser.token);
            if (walletResp && walletResp.code === 0 && walletResp.data && walletResp.data.thidGameBalanceList) {
              providerWallets = walletResp.data.thidGameBalanceList;
              for (const w of providerWallets) {
                totalBalance += Number(w.balance || 0);
              }
              totalBalance = Math.round(totalBalance * 100) / 100;
            }
          }
        } catch (e) {
          lastProvError = String(e && e.message ? e.message : e);
        }

        // Check local DB
        let user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ? OR identifier = ?')
          .bind(identifier.toLowerCase(), phoneFormatted || identifier).first();

        const now = new Date();
        const nowStr = now.toISOString();

        if (providerUser) {
          // Account verified live on upstream provider!
          const realUid = Number(providerUser.UserId) || null;
          const nickName = providerUser.NickName || '';

          if (!user) {
            const hashed = await hashPassword(password);
            await env.DB.prepare(
              'INSERT INTO users (id, identifier, password_hash, salt, invite_code, external_uid, status, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).bind(realUid, identifier.toLowerCase(), hashed, '', providerUser.parentInviteCode || null, realUid, 'active', nowStr).run();
            user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(realUid).first();
          } else {
            await env.DB.prepare('UPDATE users SET external_uid = ? WHERE id = ?').bind(realUid, user.id).run();
            user.external_uid = realUid;
          }

          // Sync real balance to D1
          await env.DB.prepare(`
            INSERT INTO balances (user_id, cash_available, bonus_available, locked_amount, version, updated_at)
            VALUES (?, ?, 0.0, 0.0, 1, ?)
            ON CONFLICT(user_id) DO UPDATE SET cash_available = ?, updated_at = ?
          `).bind(user.id, totalBalance, nowStr, totalBalance, nowStr).run();
        } else {
          // Standard local auth fallback
          if (!user || !(await verifyPassword(password, user.password_hash))) {
            return err(401, 'AUTH_REQUIRED', 'Invalid credentials');
          }
        }

        if (user.status !== 'active') {
          return err(403, 'ACCOUNT_DISABLED', 'Account is disabled or inactive');
        }

        const sid = randomHex(16);
        const family_id = randomHex(16);
        const refresh = randomToken(36);
        const refresh_hash = await sha256Hex(refresh);
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
          `).bind('USER_LOGGED_IN', user.id, sid, nowStr, JSON.stringify({
            device_id,
            provider_sync: Boolean(providerUser),
            external_uid: providerUser ? providerUser.UserId : null
          }))
        ]);

        const externalUid = providerUser ? providerUser.UserId : (user.external_uid || null);
        const upstreamToken = providerUser ? providerUser.token : null;
        const providerSessionUrl = providerUser ? providerUser.lotteryLoginUrl : null;

        const accessToken = await createJwt({
          sub: String(user.id),
          sid: sid,
          iat: nowSec(),
          exp: nowSec() + 15 * 60,
          typ: 'access',
          external_uid: externalUid,
          upstream_token: upstreamToken,
          provider_session_url: providerSessionUrl,
          // Compatibility aliases
          shreewin_uid: externalUid,
          shreewin_token: upstreamToken,
          lottery_login_url: providerSessionUrl,
        }, jwtSecret);

        const providerProfile = providerUser ? {
          uid: providerUser.UserId,
          nick_name: providerUser.NickName,
          total_balance: totalBalance,
          provider_session_url: providerUser.lotteryLoginUrl,
          parent_invite_code: providerUser.parentInviteCode,
        } : null;

        return json({
          access_token: accessToken,
          token_type: 'bearer',
          refresh_token: refresh,
          session_id: sid,
          user_id: user.id,
          external_uid: externalUid,
          provider_profile: providerProfile,
          // Compatibility aliases
          shreewin_uid: externalUid,
          shreewin_profile: providerProfile,
          lottery_login_url: providerSessionUrl,
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
      // 6. Identity (/me)
      // ----------------------------------------------------
      if (method === 'GET' && path === '/me') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess, payload } = ctx;
        const externalUid = user.external_uid || payload.external_uid || payload.shreewin_uid || null;
        const sessionUrl = payload.provider_session_url || payload.lottery_login_url || null;

        return json({
          authenticated: true,
          user_id: user.id,
          session_id: sess.id,
          invite_code: user.invite_code,
          external_uid: externalUid,
          provider_session_url: sessionUrl,
          // Backward compatibility aliases
          shreewin_uid: externalUid,
          lottery_login_url: sessionUrl,
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
        const { user, payload } = ctx;

        // If user logged in with live upstream token, refresh balance live
        const activeUpstreamToken = payload.upstream_token || payload.shreewin_token;
        if (activeUpstreamToken) {
          try {
            const walletResp = await callProviderApi('/api/webapi/GetAllwallets', {}, activeUpstreamToken);
            if (walletResp.code === 0 && walletResp.data && walletResp.data.thidGameBalanceList) {
              let sum = 0.0;
              for (const w of walletResp.data.thidGameBalanceList) {
                sum += Number(w.balance || 0);
              }
              const total = Math.round(sum * 100) / 100;
              const nowStr = nowIso();
              await env.DB.prepare('UPDATE balances SET cash_available = ?, updated_at = ? WHERE user_id = ?')
                .bind(total, nowStr, user.id).run();
            }
          } catch (e) {}
        }

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
      // WinGo Public Game APIs (NO AUTHENTICATION REQUIRED)
      // ----------------------------------------------------
      const isWingoTypes = (path === '/games/wingo/types' || path === '/wingo/types');
      const isWingoIssue = (path === '/games/wingo/issue' || path === '/wingo/issue');
      const isWingoHistory = (path === '/games/wingo/history' || path === '/wingo/history');
      const isWingoRecent = (path === '/games/wingo/recent-results' || path === '/wingo/recent-results');
      const isWingoRules = (path === '/games/wingo/rules' || path === '/wingo/rules');
      const isWingoTrxTypes = (path === '/games/wingo/trx/types' || path === '/wingo/trx/types');

      if ((method === 'GET' || method === 'POST') && (isWingoTypes || isWingoIssue || isWingoHistory || isWingoRecent || isWingoRules || isWingoTrxTypes)) {
        let reqBody = {};
        if (method === 'POST') {
          reqBody = await request.json().catch(() => ({}));
        }
        const query = url.searchParams;

        // Helper: parse game type (supports '30s', '1m', '3m', '5m', or raw typeId integer)
        const parseTypeId = (raw) => {
          if (!raw) return 1;
          const s = String(raw).toLowerCase().trim();
          if (s === '30' || s === '30s' || s === '30sec' || s === 'wingo_30s') return 30;
          if (s === '1' || s === '1m' || s === '1min' || s === 'wingo_1m') return 1;
          if (s === '2' || s === '3' || s === '3m' || s === '3min' || s === 'wingo_3m') return 2;
          if (s === '3' || s === '5' || s === '5m' || s === '5min' || s === 'wingo_5m') return 3;
          if (s === '4' || s === '10' || s === '10m' || s === '10min') return 4;
          const n = parseInt(s, 10);
          return isNaN(n) ? 1 : n;
        };

        // 1. WinGo Game Types (30s, 1m, 3m, 5m)
        if (isWingoTypes) {
          const resp = await callProviderApi('/api/webapi/GetTypeList', {});
          if (!resp || resp.code !== 0 || !resp.data) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch WinGo game types');
          }
          const types = resp.data.map(item => ({
            type_id: item.typeID,
            type_name: item.typeName,
            interval_minutes: item.intervalM,
            game_code: item.gameCode,
            bet_scope: item.scope ? item.scope.split('|').map(Number) : [],
            multipliers: item.betMultiple ? item.betMultiple.split('|').map(Number) : [],
          }));
          return json({
            success: true,
            auth_required: false,
            server_time: resp.serviceNowTime || nowIso(),
            types,
          });
        }

        // 2. WinGo Active Round / Issue with Live Countdown
        if (isWingoIssue) {
          const rawType = query.get('type_id') || query.get('type') || reqBody.type_id || reqBody.type || 1;
          const typeId = parseTypeId(rawType);
          const resp = await callProviderApi('/api/webapi/GetGameIssue', { typeId });
          if (!resp || resp.code !== 0 || !resp.data) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch current WinGo round');
          }
          const d = resp.data;
          let remainingSeconds = null;
          if (d.endTime && d.serviceTime) {
            const endMs = new Date(d.endTime.replace(/-/g, '/')).getTime();
            const servMs = new Date(d.serviceTime.replace(/-/g, '/')).getTime();
            remainingSeconds = Math.max(0, Math.floor((endMs - servMs) / 1000));
          }
          return json({
            success: true,
            auth_required: false,
            type_id: typeId,
            issue_number: d.issueNumber,
            start_time: d.startTime,
            end_time: d.endTime,
            server_time: d.serviceTime || resp.serviceNowTime,
            interval_minutes: d.intervalM,
            countdown_seconds: remainingSeconds,
          });
        }

        // 3. WinGo Historical Results (Enriched with numbers, colors, size)
        if (isWingoHistory) {
          const rawType = query.get('type_id') || query.get('type') || reqBody.type_id || reqBody.type || 1;
          const typeId = parseTypeId(rawType);
          const pageNo = parseInt(query.get('page') || reqBody.page || '1', 10);
          const pageSize = Math.min(50, Math.max(1, parseInt(query.get('size') || query.get('page_size') || reqBody.size || '10', 10)));

          const resp = await callProviderApi('/api/webapi/GetNoaverageEmerdList', {
            typeId,
            pageNo,
            pageSize,
          });
          if (!resp || resp.code !== 0 || !resp.data) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch WinGo history');
          }
          const list = (resp.data.list || []).map(item => {
            const num = Number(item.number);
            const colors = [];
            if (num === 0) colors.push('red', 'violet');
            else if (num === 5) colors.push('green', 'violet');
            else if ([1, 3, 7, 9].includes(num)) colors.push('green');
            else if ([2, 4, 6, 8].includes(num)) colors.push('red');

            return {
              issue_number: item.issueNumber,
              number: isNaN(num) ? null : num,
              colours: item.colour ? item.colour.split(',') : colors,
              size: num >= 5 ? 'big' : 'small',
              premium: item.premium ? Number(item.premium) : null,
            };
          });

          return json({
            success: true,
            auth_required: false,
            type_id: typeId,
            page_no: resp.data.pageNo,
            total_page: resp.data.totalPage,
            total_count: resp.data.totalCount,
            results: list,
          });
        }

        // 4. WinGo Recent Results (Last 5 winning numbers)
        if (isWingoRecent) {
          const rawType = query.get('type_id') || query.get('type') || reqBody.type_id || reqBody.type || 1;
          const typeId = parseTypeId(rawType);
          const resp = await callProviderApi('/api/webapi/GetLastFiveIssueNumberResult', { typeId });
          if (!resp || resp.code !== 0) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch recent WinGo results');
          }
          return json({
            success: true,
            auth_required: false,
            type_id: typeId,
            numbers: resp.data?.number || [],
          });
        }

        // 5. WinGo Rules & Multipliers
        if (isWingoRules) {
          const rawType = query.get('type_id') || query.get('type') || reqBody.type_id || reqBody.type || 1;
          const typeId = parseTypeId(rawType);
          const resp = await callProviderApi('/api/webapi/GetRuleByTypeId', { typeId });
          if (!resp || resp.code !== 0) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch WinGo rules');
          }
          return json({
            success: true,
            auth_required: false,
            type_id: typeId,
            presentation: resp.data?.gamePresentation || null,
          });
        }

        // 6. TRX WinGo Game Types
        if (isWingoTrxTypes) {
          const resp = await callProviderApi('/api/webapi/GetTRXtypeList', {});
          if (!resp || resp.code !== 0 || !resp.data) {
            return err(502, 'PROVIDER_UNAVAILABLE', resp?.msg || 'Failed to fetch TRX WinGo types');
          }
          const types = resp.data.map(item => ({
            type_id: item.typeID,
            type_name: item.typeName,
            interval_minutes: item.intervalM,
            game_code: item.gameCode,
            bet_scope: item.scope ? item.scope.split('|').map(Number) : [],
            multipliers: item.betMultiple ? item.betMultiple.split('|').map(Number) : [],
          }));
          return json({
            success: true,
            auth_required: false,
            types,
          });
        }
      }

      // ----------------------------------------------------
      // 9. Launch Game (Configurable Game Base URL & Launch URL)
      // ----------------------------------------------------
      if (method === 'POST' && path === '/games/launch') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess, payload } = ctx;

        const body = await request.json().catch(() => ({}));
        const game_id = body.game_id || 'default-game';
        const vendor = body.vendor || 'internal';
        // Configurable Game Base URL: Priority is (1) body.game_base_url, (2) env.GAME_BASE_URL, (3) default
        const gameBaseUrl = (body.game_base_url || env.GAME_BASE_URL || defaultGameBaseUrl).replace(/\/+$/, '');

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
          `).bind('GAME_LAUNCH_INITIATED', user.id, sess.id, gameSessionId, nowStr, JSON.stringify({ game_id, vendor, game_base_url: gameBaseUrl }))
        ]);

        // Construct dynamic game launch URL
        let launchUrl = `${gameBaseUrl}/?game_id=${encodeURIComponent(game_id)}&session_id=${gameSessionId}&ticket=${launchTicket}`;
        if (payload.lottery_login_url) {
          launchUrl = payload.lottery_login_url;
        }

        return json({
          game_session_id: gameSessionId,
          state: 'PENDING',
          expires_at: gameExpires,
          launch_ticket: launchTicket,
          ticket_expires_at: ticketExpires,
          game_base_url: gameBaseUrl,
          launch_url: launchUrl,
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
      // 12. Authoritative State (/system/user-state)
      // ----------------------------------------------------
      if (method === 'GET' && path === '/system/user-state') {
        const ctx = await requireContext();
        if (ctx.error) return ctx.error;
        const { user, sess, payload } = ctx;

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

        const extUid = payload.external_uid || payload.shreewin_uid || user.external_uid || user.id;

        return json({
          user: {
            id: user.id,
            registered: true,
            external_uid: extUid,
            shreewin_uid: extUid,
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

      return err(404, 'NOT_FOUND', `Endpoint not found: ${method} ${path}`);
    } catch (e) {
      return err(500, 'INTERNAL_ERROR', e.message || 'Server error');
    }
  }
};

// ---------------------------------------------------------
// Pure JavaScript MD5 Implementation (Standard RFC 1321)
// ---------------------------------------------------------
function md5(string) {
  function md5_RotateLeft(lValue, iShiftBits) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }
  function md5_AddUnsigned(lX, lY) {
    var lX4, lY4, lX8, lY8, lResult;
    lX8 = (lX & 0x80000000);
    lY8 = (lY & 0x80000000);
    lX4 = (lX & 0x40000000);
    lY4 = (lY & 0x40000000);
    lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
    if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
      else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
    } else return (lResult ^ lX8 ^ lY8);
  }
  function md5_F(x, y, z) { return (x & y) | ((~x) & z); }
  function md5_G(x, y, z) { return (x & z) | (y & (~z)); }
  function md5_H(x, y, z) { return (x ^ y ^ z); }
  function md5_I(x, y, z) { return (y ^ (x | (~z))); }
  function md5_FF(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_F(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_GG(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_G(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_HH(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_H(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_II(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_I(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_ConvertToWordArray(string) {
    var lWordCount;
    var lMessageLength = string.length;
    var lNumberOfWords_temp1 = lMessageLength + 8;
    var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    var lWordArray = Array(lNumberOfWords - 1);
    var lBytePosition = 0;
    var lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }
  function md5_WordToHex(lValue) {
    var WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = "0" + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
    }
    return WordToHexValue;
  }
  var x = md5_ConvertToWordArray(string);
  var a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  var S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  var S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  var S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  var S41 = 6, S42 = 10, S43 = 15, S44 = 21;
  for (var k = 0; k < x.length; k += 16) {
    var AA = a, BB = b, CC = c, DD = d;
    a = md5_FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
    d = md5_FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
    c = md5_FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
    b = md5_FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
    a = md5_FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
    d = md5_FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
    c = md5_FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
    b = md5_FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
    a = md5_FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
    d = md5_FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
    c = md5_FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
    b = md5_FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
    a = md5_FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
    d = md5_FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
    c = md5_FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
    b = md5_FF(b, c, d, a, x[k + 15], S14, 0x49B40821);

    a = md5_GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
    d = md5_GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
    c = md5_GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
    b = md5_GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
    a = md5_GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
    d = md5_GG(d, a, b, c, x[k + 10], S22, 0x2441453);
    c = md5_GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
    b = md5_GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
    a = md5_GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
    d = md5_GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
    c = md5_GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
    b = md5_GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
    a = md5_GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
    d = md5_GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
    c = md5_GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
    b = md5_GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);

    a = md5_HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
    d = md5_HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
    c = md5_HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
    b = md5_HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
    a = md5_HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
    d = md5_HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
    c = md5_HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
    b = md5_HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
    a = md5_HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
    d = md5_HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
    c = md5_HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
    b = md5_HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
    a = md5_HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
    d = md5_HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
    c = md5_HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
    b = md5_HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);

    a = md5_II(a, b, c, d, x[k + 0], S41, 0xF4292244);
    d = md5_II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
    c = md5_II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
    b = md5_II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
    a = md5_II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
    d = md5_II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
    c = md5_II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
    b = md5_II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
    a = md5_II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
    d = md5_II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
    c = md5_II(c, d, a, b, x[k + 6], S43, 0xA3014314);
    b = md5_II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
    a = md5_II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
    d = md5_II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
    c = md5_II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
    b = md5_II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
    a = md5_AddUnsigned(a, AA);
    b = md5_AddUnsigned(b, BB);
    c = md5_AddUnsigned(c, CC);
    d = md5_AddUnsigned(d, DD);
  }
  return (md5_WordToHex(a) + md5_WordToHex(b) + md5_WordToHex(c) + md5_WordToHex(d)).toLowerCase();
}

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
