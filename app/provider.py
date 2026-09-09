import asyncio
import hashlib
import json
import secrets
import time
from typing import Any
import httpx
from .core import settings

def sign_provider_payload(data: dict[str, Any]) -> dict[str, Any]:
    t = dict(data)
    t.pop('signature', None)
    t.pop('timestamp', None)
    t['language'] = 1
    t['random'] = secrets.token_hex(8)
    sorted_keys = sorted(t.keys())
    cleaned = {}
    for k in sorted_keys:
        v = t[k]
        if v is not None and v != '' and k not in ('signature', 'track', 'xosoBettingData'):
            cleaned[k] = 0 if v == 0 else v
    raw = json.dumps(cleaned, separators=(',', ':'))
    t['signature'] = hashlib.md5(raw.encode('utf-8')).hexdigest().upper()[:32]
    t['timestamp'] = int(time.time())
    return t

def call_provider_api(endpoint: str, data: dict[str, Any] | None = None, token: str | None = None, client_ip: str | None = None) -> dict[str, Any]:
    payload = sign_provider_payload(data or {})
    # ponytail: fixed fallback IP, pass client_ip when caller has the request; per-request IP if upstream enforces it
    ip = client_ip or '103.44.118.79'
    headers = _headers(ip, token)
    
    url = f'{settings.provider_api_url.rstrip("/")}{endpoint}'
    try:
        resp = _shared_sync_client().post(url, json=payload, headers=headers)
        return resp.json()
    except Exception as e:
        return {'code': -1, 'msg': str(e), 'data': None}

# ponytail: in-memory per-process TTL; shared cache service if multi-worker consistency matters
_PUBLIC_TTL = {
    '/api/webapi/GetTypeList': 3600,
    '/api/webapi/GetTRXtypeList': 3600,
    '/api/webapi/GetRuleByTypeId': 3600,
    '/api/webapi/GetGameIssue': 2,
    '/api/webapi/GetNoaverageEmerdList': 5,
    '/api/webapi/GetLastFiveIssueNumberResult': 5,
}
_TTL_CACHE: dict[str, tuple[float, Any]] = {}
_sync_client: httpx.Client | None = None
_async_clients: dict[int, httpx.AsyncClient] = {}

def _cache_key(endpoint: str, data: dict[str, Any] | None, token: str | None) -> str:
    if token:
        return ''
    return endpoint + ':' + json.dumps(data or {}, sort_keys=True, separators=(',', ':'))

def _cache_get(key: str) -> Any | None:
    if not key:
        return None
    hit = _TTL_CACHE.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    _TTL_CACHE.pop(key, None)
    return None

def _cache_set(key: str, value: Any, ttl: int) -> None:
    if key and ttl > 0:
        _TTL_CACHE[key] = (time.time() + ttl, value)

def _shared_sync_client() -> httpx.Client:
    global _sync_client
    if _sync_client is None:
        _sync_client = httpx.Client(timeout=10.0)
    return _sync_client

async def _shared_async_client() -> httpx.AsyncClient:
    # one client per running loop: TestClient portals each own a loop, sharing one breaks on loop close
    key = id(asyncio.get_running_loop())
    client = _async_clients.get(key)
    if client is None:
        client = httpx.AsyncClient(timeout=10.0)
        _async_clients[key] = client
    return client

def _headers(ip: str, token: str | None) -> dict[str, str]:
    h = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Origin': settings.provider_origin,
        'Referer': settings.provider_origin.rstrip('/') + '/',
        'Content-Type': 'application/json',
        'AR-REAL-IP': ip,
        'X-Real-IP': ip,
        'X-Forwarded-For': ip,
    }
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h

async def call_provider_api_async(endpoint: str, data: dict[str, Any] | None = None, token: str | None = None, client_ip: str | None = None) -> dict[str, Any]:
    ttl = _PUBLIC_TTL.get(endpoint, 0)
    key = _cache_key(endpoint, data, token)
    hit = _cache_get(key)
    if hit is not None:
        return hit
    payload = sign_provider_payload(data or {})
    ip = client_ip or '103.44.118.79'
    url = f'{settings.provider_api_url.rstrip("/")}{endpoint}'
    try:
        client = await _shared_async_client()
        resp = await client.post(url, json=payload, headers=_headers(ip, token))
        out = resp.json()
    except Exception as e:
        return {'code': -1, 'msg': str(e), 'data': None}
    _cache_set(key, out, ttl)
    return out

def parse_wingo_type_id(raw: Any) -> int:
    if not raw:
        return 1
    s = str(raw).lower().strip()
    if s in ('30', '30s', '30sec', 'wingo_30s'):
        return 30
    if s in ('1', '1m', '1min', 'wingo_1m'):
        return 1
    if s in ('2', '3m', '3min', 'wingo_3m'):
        return 2
    if s in ('3', '5m', '5min', 'wingo_5m'):
        return 3
    if s in ('4', '10', '10m', '10min'):
        return 4
    try:
        return int(s)
    except ValueError:
        return 1

def enrich_wingo_result(item: dict[str, Any]) -> dict[str, Any]:
    if not item:
        return {}
    num_raw = item.get('number') if item.get('number') is not None else item.get('openNumber')
    try:
        num = int(num_raw) if num_raw is not None else None
    except (ValueError, TypeError):
        num = None

    colors: list[str] = []
    if num == 0:
        colors = ['red', 'violet']
    elif num == 5:
        colors = ['green', 'violet']
    elif num in (1, 3, 7, 9):
        colors = ['green']
    elif num in (2, 4, 6, 8):
        colors = ['red']

    raw_colour = item.get('colour')
    assigned_colors = raw_colour.split(',') if raw_colour else colors
    size = 'big' if (num is not None and num >= 5) else 'small'

    premium_raw = item.get('premium')
    try:
        premium = int(premium_raw) if premium_raw is not None else None
    except (ValueError, TypeError):
        premium = None

    return {
        'issue_number': item.get('issueNumber'),
        'number': num,
        'colours': assigned_colors,
        'size': size,
        'premium': premium,
    }
