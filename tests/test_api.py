from decimal import Decimal
import os
import threading

os.environ['DATABASE_URL'] = 'sqlite:///./test_user_state.db'
os.environ['JWT_SECRET_KEY'] = 'test-secret-key-with-enough-entropy'

from fastapi.testclient import TestClient
from app.main import app
from app.core import Base, engine, SessionLocal, Balance, GameSession, utcnow
from datetime import timedelta

Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
client = TestClient(app)

def auth_user(identifier='alice@example.com', password='a-long-test-password', device_id='test-device'):
    r = client.post('/auth/login', json={'identifier': identifier, 'password': password, 'device_id': device_id})
    assert r.status_code == 200, r.text
    data = r.json()
    return data['access_token'], data['refresh_token'], data['session_id']

def setup_function():
    from app.main import _LOGIN_ATTEMPTS
    _LOGIN_ATTEMPTS.clear()

def setup_module():
    r = client.post('/auth/register', json={'identifier': 'alice@example.com', 'password': 'a-long-test-password'})
    assert r.status_code == 201
    r_bob = client.post('/auth/register', json={'identifier': 'bob@example.com', 'password': 'a-long-test-password'})
    assert r_bob.status_code == 201

def test_login_and_initial_balance():
    token, refresh, sid = auth_user()
    h = {'Authorization': f'Bearer {token}'}
    me = client.get('/me', headers=h).json()
    assert me['authenticated'] is True
    assert me['session_id'] == sid

    b = client.get('/wallet/available-balance', headers=h).json()
    assert float(b['available_for_game']) == 0
    assert b['balance_version'] == 1

def test_refresh_token_rotation_and_reuse_detection():
    token, refresh_1, sid = auth_user()
    
    # 1. Rotate refresh token once
    r1 = client.post('/auth/refresh', json={'refresh_token': refresh_1})
    assert r1.status_code == 200, r1.text
    data1 = r1.json()
    assert 'access_token' in data1
    assert 'refresh_token' in data1
    refresh_2 = data1['refresh_token']
    assert refresh_2 != refresh_1

    # 2. Use the new refresh token -> should succeed
    r2 = client.post('/auth/refresh', json={'refresh_token': refresh_2})
    assert r2.status_code == 200
    refresh_3 = r2.json()['refresh_token']
    assert refresh_3 != refresh_2

    # 3. Reuse old refresh_1 -> REUSE DETECTED!
    r_reuse = client.post('/auth/refresh', json={'refresh_token': refresh_1})
    assert r_reuse.status_code == 401
    assert r_reuse.json()['detail']['code'] == 'AUTH_REVOKED'

    # 4. Entire session family is now revoked; even refresh_3 must fail
    r_family_dead = client.post('/auth/refresh', json={'refresh_token': refresh_3})
    assert r_family_dead.status_code == 401
    assert r_family_dead.json()['detail']['code'] == 'AUTH_REVOKED'

def test_launch_ticket_lifecycle_and_game_lease():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    # 1. Launch creates session in PENDING and generates launch ticket
    launch = client.post('/games/launch', headers=h, json={'game_id': 'roulette', 'vendor': 'internal'})
    assert launch.status_code == 200
    launch_data = launch.json()
    gid = launch_data['game_session_id']
    ticket = launch_data['launch_ticket']
    assert launch_data['state'] == 'PENDING'
    assert bool(ticket) is True

    # 2. Consume ticket activates the game session
    consume = client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})
    assert consume.status_code == 200
    assert consume.json()['state'] == 'ACTIVE'

    # 3. Consuming same ticket again is rejected
    consume_again = client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})
    assert consume_again.status_code == 409
    assert consume_again.json()['detail']['code'] == 'LAUNCH_TICKET_CONSUMED'

    # 4. Heartbeat lease succeeds
    hb = client.post(f'/games/{gid}/heartbeat', headers=h)
    assert hb.status_code == 200
    assert hb.json()['state'] == 'ACTIVE'

    # 5. User state reports active game
    state = client.get('/system/user-state', headers=h).json()
    assert state['game']['inside_game'] is True
    assert state['game']['game_session_id'] == gid

def test_game_session_session_binding():
    # Session A launches game
    token_a, _, _ = auth_user('alice@example.com', device_id='device-a')
    ha = {'Authorization': f'Bearer {token_a}'}
    launch = client.post('/games/launch', headers=ha, json={'game_id': 'blackjack'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=ha, json={'game_session_id': gid, 'launch_ticket': ticket})

    # Session B (different login session for alice) tries to heartbeat session A's game
    token_b, _, _ = auth_user('alice@example.com', device_id='device-b')
    hb = {'Authorization': f'Bearer {token_b}'}
    r = client.post(f'/games/{gid}/heartbeat', headers=hb)
    assert r.status_code == 409
    assert r.json()['detail']['code'] == 'GAME_SESSION_MISMATCH'

def test_action_authorization_and_atomic_debit():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    # Fund balance for alice directly in DB
    db = SessionLocal()
    b = db.get(Balance, 1)
    b.cash_available = 100.00
    db.commit()
    db.close()

    # Launch & activate game
    launch = client.post('/games/launch', headers=h, json={'game_id': 'slots'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})

    # 1. Execute action debit with idempotency key
    action_payload = {'client_request_id': 'req-debit-001', 'amount': '25.00'}
    res = client.post(
        f'/game-sessions/{gid}/actions/spin',
        headers={**h, 'Idempotency-Key': 'idem-spin-001'},
        json=action_payload,
    )
    assert res.status_code == 200, res.text
    res_data = res.json()
    assert res_data['status'] == 'COMPLETED'
    assert res_data['debited_amount'] == 25.0
    assert res_data['available_balance'] == 75.0
    assert res_data['balance_version'] == 2

    # 2. Replay with identical Idempotency-Key returns cached response without double debit
    res_retry = client.post(
        f'/game-sessions/{gid}/actions/spin',
        headers={**h, 'Idempotency-Key': 'idem-spin-001'},
        json=action_payload,
    )
    assert res_retry.status_code == 200
    assert res_retry.json() == res_data

    # Check balance is still 75.0
    bal = client.get('/wallet/available-balance', headers=h).json()
    assert bal['available_for_game'] == 75.0
    assert bal['balance_version'] == 2

    # 3. Using same client_request_id with a DIFFERENT idempotency key is blocked as replayed nonce
    res_replayed_nonce = client.post(
        f'/game-sessions/{gid}/actions/spin',
        headers={**h, 'Idempotency-Key': 'idem-spin-002'},
        json=action_payload,
    )
    assert res_replayed_nonce.status_code == 409
    assert res_replayed_nonce.json()['detail']['code'] == 'REQUEST_REPLAYED'

    # 4. Attempting to debit more than available fails closed
    over_debit = client.post(
        f'/game-sessions/{gid}/actions/spin',
        headers={**h, 'Idempotency-Key': 'idem-spin-003'},
        json={'client_request_id': 'req-debit-002', 'amount': '500.00'},
    )
    assert over_debit.status_code == 409
    assert over_debit.json()['detail']['code'] == 'INSUFFICIENT_BALANCE'

def test_game_settlement():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    launch = client.post('/games/launch', headers=h, json={'game_id': 'poker'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})

    bal_before = client.get('/wallet/available-balance', headers=h).json()['available_for_game']

    settle = client.post(
        f'/games/{gid}/settle',
        headers=h,
        json={'client_request_id': 'settle-req-001', 'payout_amount': '50.00'},
    )
    assert settle.status_code == 200
    assert settle.json()['state'] == 'SETTLED'

    bal_after = client.get('/wallet/available-balance', headers=h).json()['available_for_game']
    assert bal_after == bal_before + 50.0

def test_heartbeat_lease_expiration():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    launch = client.post('/games/launch', headers=h, json={'game_id': 'baccarat'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})

    # Artificially age the heartbeat in the database
    db = SessionLocal()
    gs = db.get(GameSession, gid)
    gs.last_heartbeat_at = utcnow() - timedelta(seconds=120)
    db.commit()
    db.close()

    # Heartbeat after lease expiration is rejected and transitions to EXPIRED
    hb_late = client.post(f'/games/{gid}/heartbeat', headers=h)
    assert hb_late.status_code == 409
    assert hb_late.json()['detail']['code'] == 'GAME_SESSION_EXPIRED'

    # Action after lease expiration is also rejected
    act = client.post(
        f'/game-sessions/{gid}/actions/bet',
        headers=h,
        json={'client_request_id': 'req-expired-lease', 'amount': '1.00'},
    )
    assert act.status_code == 409
    assert act.json()['detail']['code'] == 'GAME_SESSION_REQUIRED'

def test_logout_revokes_all():
    token, _, sid = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    launch = client.post('/games/launch', headers=h, json={'game_id': 'craps'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})

    # Logout
    logout_res = client.post('/auth/logout', headers=h)
    assert logout_res.status_code == 200
    assert logout_res.json()['logged_out'] is True

    # Token is revoked
    assert client.get('/me', headers=h).status_code == 401

    # Associated game session is REVOKED
    db = SessionLocal()
    gs = db.get(GameSession, gid)
    assert gs.state == 'REVOKED'
    db.close()

def test_concurrent_debits_prevent_double_spending():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}

    # Set balance to exactly 50.00
    db = SessionLocal()
    b = db.get(Balance, 1)
    b.cash_available = 50.00
    db.commit()
    db.close()

    launch = client.post('/games/launch', headers=h, json={'game_id': 'concurrent-test'})
    gid = launch.json()['game_session_id']
    ticket = launch.json()['launch_ticket']
    client.post('/games/tickets/consume', headers=h, json={'game_session_id': gid, 'launch_ticket': ticket})

    results = []

    def debit_worker(req_id, idem_key):
        c = TestClient(app)
        res = c.post(
            f'/game-sessions/{gid}/actions/bet',
            headers={**h, 'Idempotency-Key': idem_key},
            json={'client_request_id': req_id, 'amount': '40.00'},
        )
        results.append(res.status_code)

    # Launch two threads simultaneously attempting to debit 40.00 from 50.00 balance
    t1 = threading.Thread(target=debit_worker, args=('concurrent-req-1', 'idem-c-1'))
    t2 = threading.Thread(target=debit_worker, args=('concurrent-req-2', 'idem-c-2'))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one must succeed (200) and one must be rejected (409)
    assert 200 in results
    assert 409 in results
    assert results.count(200) == 1
    assert results.count(409) == 1

    # Remaining balance must be exactly 10.00
    final_bal = client.get('/wallet/available-balance', headers=h).json()['available_for_game']
    assert final_bal == 10.0

def test_healthz_and_configurable_urls():
    r = client.get('/healthz')
    assert r.status_code == 200
    data = r.json()
    assert data['status'] == 'ok'
    assert 'provider_api_url' in data
    assert 'game_base_url' in data

def test_game_launch_custom_game_base_url():
    token, _, _ = auth_user()
    h = {'Authorization': f'Bearer {token}'}
    custom_url = 'https://custom-game-domain.example.com'
    r = client.post(
        '/games/launch',
        headers=h,
        json={'game_id': 'wingo-1m', 'vendor': 'internal', 'game_base_url': custom_url}
    )
    assert r.status_code == 200
    data = r.json()
    assert 'launch_url' in data
    assert data['launch_url'].startswith(custom_url)
    assert 'session_id=' in data['launch_url']
    assert 'ticket=' in data['launch_url']

def test_wingo_public_endpoints_no_auth():
    # 1. Types
    r = client.get('/games/wingo/types')
    assert r.status_code == 200
    d = r.json()
    assert d['success'] is True
    assert d['auth_required'] is False
    assert len(d['types']) >= 1

    # 2. Issue (1m)
    r2 = client.get('/games/wingo/issue?type=1m')
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2['success'] is True
    assert d2['auth_required'] is False
    assert d2['type_id'] == 1
    assert 'issue_number' in d2

    # 3. History
    r3 = client.get('/games/wingo/history?type=1m&size=3')
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3['success'] is True
    assert d3['auth_required'] is False
    assert len(d3['results']) <= 3

    # 4. Recent results
    r4 = client.get('/games/wingo/recent-results?type=1m')
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4['auth_required'] is False
    assert 'numbers' in d4

def test_wingo_live_stream_sse():
    with client.stream('GET', '/games/wingo/live-stream?type=1m&limit=1') as r:
        assert r.status_code == 200
        assert 'text/event-stream' in r.headers['content-type']
        lines = []
        for line in r.iter_lines():
            if line:
                lines.append(line)
        combined = '\n'.join(lines)
        assert 'event: connected' in combined or 'event: tick' in combined


def test_dynamic_ota_config():
    # 1. Default config
    r = client.get('/app/config')
    assert r.status_code == 200
    d = r.json()
    assert d['app_active'] is True
    assert 'branding' in d
    assert d['branding']['panel_name'] == 'NEXY'
    assert 'deposit_url' in d

    # 2. Update config for channel v2
    r_update = client.post('/admin/app-config', json={
        'channel': 'v2',
        'broadcast_notice': 'Special VIP bonus active!',
        'branding_panel_name': 'NEXY_PRO',
        'min_unlock_balance': 100.0,
    })
    assert r_update.status_code == 200
    d_up = r_update.json()
    assert d_up['success'] is True
    assert d_up['config']['branding']['panel_name'] == 'NEXY_PRO'
    assert d_up['config']['min_unlock_balance'] == 100.0

    # 3. Fetch channel v2 config
    r_v2 = client.get('/api/config?channel=v2')
    assert r_v2.status_code == 200
    assert r_v2.json()['broadcast_notice'] == 'Special VIP bonus active!'


def test_device_telemetry_heartbeat_and_check_user():
    # 1. Post heartbeat from device
    r_hb = client.post('/api/heartbeat', json={
        'userId': 'test_player_99',
        'userName': 'WhaleOne',
        'phone': '9876543210',
        'balance': 350.75,
        'game': 'WinGo 1-Min',
        'channel': 'v2',
        'device': {
            'deviceId': 'test_dev_uuid_123',
            'brand': 'Google',
            'model': 'Pixel 8',
            'osVersion': 'Android 14',
            'isEmulator': False,
            'isRooted': False
        }
    })
    assert r_hb.status_code == 200
    d_hb = r_hb.json()
    assert d_hb['success'] is True
    assert d_hb['balance'] == 350.75

    # 2. Check user access (should be unlocked because balance >= min_unlock_balance)
    r_chk = client.post('/api/check-user', json={
        'userId': 'test_player_99',
        'phone': '9876543210',
        'channel': 'v2'
    })
    assert r_chk.status_code == 200
    d_chk = r_chk.json()
    assert d_chk['allowed'] is True
    assert d_chk['unlocked'] is True
    assert d_chk['balance'] == 350.75

    # 3. Admin telemetry dashboard
    r_adm = client.get('/admin/telemetry?channel=all')
    assert r_adm.status_code == 200
    d_adm = r_adm.json()
    assert d_adm['summary']['total_tracked'] >= 1
    assert len(d_adm['whales']) >= 1
    top_whale = d_adm['whales'][0]
    assert top_whale['user_id'] == 'test_player_99'


def test_wingo_prediction_engine():
    # 1. GET prediction for 1-Min
    r = client.get('/games/wingo/prediction?typeId=1&issueNumber=202609081055')
    assert r.status_code == 200
    d = r.json()
    assert d['success'] is True
    assert d['issue_number'] == '202609081055'
    assert 'prediction' in d
    pred = d['prediction']
    assert pred['size'] in ('BIG', 'SMALL')
    assert pred['color'] in ('GREEN', 'RED', 'VIOLET')
    assert pred['confidence_rate'] >= 80.0
    assert len(pred['recommended_numbers']) > 0

    # 2. POST prediction for 30s
    r_post = client.post('/wingo/prediction', json={'type_id': 30})
    assert r_post.status_code == 200
    d_post = r_post.json()
    assert d_post['success'] is True
    assert d_post['type_id'] == 30
    assert d_post['prediction']['size'] in ('BIG', 'SMALL')


def test_ota_script_hot_patching():
    # 1. GET default script
    r = client.get('/app/scripts/game_hook.js')
    assert r.status_code == 200
    assert 'Remote Game Hook' in r.text
    etag = r.headers.get('etag')
    assert etag is not None

    # 2. ETag validation (304 Not Modified)
    r_304 = client.get('/app/scripts/game_hook.js', headers={'If-None-Match': etag})
    assert r_304.status_code == 304

    # 3. Update script via admin
    custom_content = "// Custom Hot Patch v2.2\nwindow.__HOT_PATCHED__ = true;"
    r_up = client.post('/admin/scripts/game_hook.js', json={'content': custom_content})
    assert r_up.status_code == 200
    d_up = r_up.json()
    assert d_up['success'] is True

    # 4. Fetch updated script
    r_new = client.get('/app/scripts/game_hook.js')
    assert r_new.status_code == 200
    assert 'Custom Hot Patch v2.2' in r_new.text
    assert r_new.headers.get('etag') != etag


def test_in_app_apk_updater():
    # 1. Baseline version check (up to date)
    r = client.get('/app/version-check?flavor=v1&version_code=7')
    assert r.status_code == 200
    d = r.json()
    assert d['has_update'] is False

    # 2. Register a new release v1.3.1 (version_code 8)
    r_rel = client.post('/admin/app-releases', json={
        'flavor': 'v1',
        'version_code': 8,
        'version_name': '1.3.1',
        'force_update': False,
        'download_url': 'https://pub-example.r2.dev/shreewin-v1-1.3.1.apk',
        'changelog': '• Improved Dragon Streak engine\n• Real-time OTA hot-patching',
        'sha256': 'abc1234567890'
    })
    assert r_rel.status_code == 200
    assert r_rel.json()['success'] is True

    # 3. Version check for client on version_code 7 (should flag has_update)
    r_chk = client.get('/app/version-check?flavor=v1&version_code=7')
    assert r_chk.status_code == 200
    d_chk = r_chk.json()
    assert d_chk['has_update'] is True
    assert d_chk['force_update'] is False
    assert d_chk['latest_version_code'] == 8
    assert d_chk['latest_version_name'] == '1.3.1'
    assert 'shreewin-v1-1.3.1.apk' in d_chk['download_url']
    assert 'Dragon Streak' in d_chk['changelog']

    # 4. Version check for client already on version_code 8
    r_chk8 = client.get('/app/version-check?flavor=v1&version_code=8')
    assert r_chk8.status_code == 200
    assert r_chk8.json()['has_update'] is False





