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

def call_provider_api(endpoint: str, data: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
    payload = sign_provider_payload(data or {})
    client_ip = '103.44.118.79'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Origin': settings.provider_origin,
        'Referer': settings.provider_origin.rstrip('/') + '/',
        'Content-Type': 'application/json',
        'AR-REAL-IP': client_ip,
        'X-Real-IP': client_ip,
        'X-Forwarded-For': client_ip,
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    url = f'{settings.provider_api_url.rstrip("/")}{endpoint}'
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            return resp.json()
    except Exception as e:
        return {'code': -1, 'msg': str(e), 'data': None}

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
