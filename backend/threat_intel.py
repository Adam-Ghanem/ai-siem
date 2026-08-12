from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
OTX_URL_TEMPLATE = 'https://otx.alienvault.com/api/v1/indicators/{family}/{indicator}/general'
DEFAULT_TIMEOUT_SECONDS = float(os.getenv('AI_SIEM_THREAT_INTEL_TIMEOUT_SECONDS', '3'))
CACHE_TTL_SECONDS = int(os.getenv('AI_SIEM_THREAT_INTEL_CACHE_TTL_SECONDS', '900'))
MAX_CACHE_ENTRIES = int(os.getenv('AI_SIEM_THREAT_INTEL_MAX_CACHE_ENTRIES', '2048'))
MAX_INDICATORS_PER_REQUEST = int(os.getenv('AI_SIEM_THREAT_INTEL_MAX_INDICATORS', '50'))


@dataclass(frozen=True)
class ProviderResponse:
    provider: str
    indicator: str
    status: str
    malicious: bool | None
    confidence: float | None
    details: dict[str, Any]
    fetched_at: str
    error: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(value: object) -> str:
    return str(value or 'provider request failed').replace('\n', ' ')[:256]


def _valid_global_ip(value: object) -> str | None:
    try:
        ip = ip_address(str(value).strip())
    except ValueError:
        return None
    if not ip.is_global:
        return None
    return str(ip)


def normalize_indicators(indicators: list[object]) -> list[str]:
    normalized = []
    seen = set()
    for value in indicators[:MAX_INDICATORS_PER_REQUEST]:
        indicator = _valid_global_ip(value)
        if indicator and indicator not in seen:
            seen.add(indicator)
            normalized.append(indicator)
    return normalized


def _request_json(
    url: str,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    if params:
        url = f'{url}?{urlencode(params)}'
    request = UrlRequest(url, headers=headers, method='GET')
    with urlopen(request, timeout=timeout) as response:
        body = response.read(512 * 1024)
        data = json.loads(body.decode('utf-8'))
        return int(response.status), data if isinstance(data, dict) else {}


class ThreatIntelEnricher:
    def __init__(
        self,
        abuseipdb_key: str | None = None,
        otx_key: str | None = None,
        request_json: Callable[..., tuple[int, dict[str, Any]]] = _request_json,
    ) -> None:
        self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY', '').strip()
        self.otx_key = otx_key or os.getenv('OTX_API_KEY', '').strip()
        self.request_json = request_json
        self._cache: OrderedDict[tuple[str, str], tuple[float, ProviderResponse]] = OrderedDict()
        self._lock = threading.Lock()

    def configured_providers(self) -> list[str]:
        providers = []
        if self.abuseipdb_key:
            providers.append('abuseipdb')
        if self.otx_key or os.getenv('AI_SIEM_OTX_ENABLED', 'false').lower() == 'true':
            providers.append('otx')
        return providers

    def _cache_get(self, provider: str, indicator: str) -> ProviderResponse | None:
        key = (provider, indicator)
        with self._lock:
            value = self._cache.get(key)
            if not value:
                return None
            timestamp, response = value
            if time.time() - timestamp > CACHE_TTL_SECONDS:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return response

    def _cache_put(self, response: ProviderResponse) -> None:
        key = (response.provider, response.indicator)
        with self._lock:
            self._cache[key] = (time.time(), response)
            self._cache.move_to_end(key)
            while len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)

    def _disabled(self, provider: str, indicator: str) -> ProviderResponse:
        return ProviderResponse(
            provider, indicator, 'disabled', None, None, {}, _now(), 'provider_not_configured'
        )

    def _error(self, provider: str, indicator: str, exc: object) -> ProviderResponse:
        return ProviderResponse(
            provider, indicator, 'error', None, None, {}, _now(), _safe_error(exc)
        )

    def _abuseipdb(self, indicator: str) -> ProviderResponse:
        cached = self._cache_get('abuseipdb', indicator)
        if cached:
            return cached
        if not self.abuseipdb_key:
            return self._disabled('abuseipdb', indicator)
        try:
            _, payload = self.request_json(
                ABUSEIPDB_URL,
                {'Accept': 'application/json', 'Key': self.abuseipdb_key},
                {'ipAddress': indicator, 'maxAgeInDays': '90'},
            )
            data = payload.get('data') if isinstance(payload.get('data'), dict) else {}
            score = data.get('abuseConfidenceScore')
            score_float = float(score) / 100 if score is not None else None
            response = ProviderResponse(
                'abuseipdb',
                indicator,
                'hit' if data else 'not_found',
                bool(score is not None and float(score) >= 50),
                score_float,
                {
                    'country_code': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'is_tor': data.get('isTor'),
                    'total_reports': data.get('totalReports'),
                    'last_reported_at': data.get('lastReportedAt'),
                },
                _now(),
            )
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            response = self._error('abuseipdb', indicator, exc)
        self._cache_put(response)
        return response

    def _otx(self, indicator: str) -> ProviderResponse:
        cached = self._cache_get('otx', indicator)
        if cached:
            return cached
        headers = {'Accept': 'application/json'}
        if self.otx_key:
            headers['X-OTX-API-KEY'] = self.otx_key
        if not self.otx_key and os.getenv('AI_SIEM_OTX_ENABLED', 'false').lower() != 'true':
            return self._disabled('otx', indicator)
        family = 'IPv6' if ':' in indicator else 'IPv4'
        try:
            _, payload = self.request_json(
                OTX_URL_TEMPLATE.format(family=family, indicator=indicator),
                headers,
            )
            pulse_info = payload.get('pulse_info') if isinstance(payload.get('pulse_info'), dict) else {}
            pulse_count = int(pulse_info.get('count') or 0)
            reputation = payload.get('reputation') if isinstance(payload.get('reputation'), dict) else {}
            response = ProviderResponse(
                'otx',
                indicator,
                'hit' if pulse_count or reputation else 'not_found',
                bool(pulse_count or reputation.get('adversary')),
                min(1.0, pulse_count / 10) if pulse_count else 0.0,
                {
                    'pulse_count': pulse_count,
                    'reputation': reputation.get('adversary') or reputation.get('score'),
                    'sections': payload.get('sections') if isinstance(payload.get('sections'), list) else [],
                },
                _now(),
            )
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            response = self._error('otx', indicator, exc)
        self._cache_put(response)
        return response

    def enrich(self, indicators: list[object]) -> list[dict[str, Any]]:
        normalized = normalize_indicators(indicators)
        results: list[dict[str, Any]] = []
        for indicator in normalized:
            for provider in self.configured_providers():
                response = self._abuseipdb(indicator) if provider == 'abuseipdb' else self._otx(indicator)
                results.append({
                    'provider': response.provider,
                    'indicator': response.indicator,
                    'status': response.status,
                    'malicious': response.malicious,
                    'confidence': response.confidence,
                    'details': response.details,
                    'fetched_at': response.fetched_at,
                    'error': response.error,
                })
        return results


THREAT_INTEL = ThreatIntelEnricher()
