from __future__ import annotations

from urllib.parse import unquote

from . import security


class AuditLogIntegrityError(RuntimeError):
    """Raised when audit records cannot be trusted because the chain is invalid."""


def _parse_record(line: str) -> dict[str, str]:
    record: dict[str, str] = {}
    for field in line.strip().split():
        key, separator, value = field.partition('=')
        if separator and key:
            record[key] = unquote(value)
    return record


def _verified_audit_lines() -> list[str]:
    """Return one integrity-verified snapshot of the audit log.

    Verification and reading share the same in-process and file locks used by
    audit writers. This prevents a valid log from being verified and then
    changed by another AI-SIEM worker before the search path reads it.
    """
    path = security.AUDIT_LOG_PATH
    with security._AUDIT_LOCK:
        with security._audit_file_lock(path):
            if not path.exists():
                return []
            valid, _ = security._audit_chain_state(path)
            if not valid:
                raise AuditLogIntegrityError('Audit log integrity check failed')
            return path.read_text(encoding='utf-8').splitlines()


def search_audit_records(
    *,
    principal: str | None = None,
    action: str | None = None,
    result: str | None = None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, str]], int]:
    matches: list[dict[str, str]] = []
    total = 0
    for raw_line in _verified_audit_lines():
        line = raw_line.strip()
        if not line:
            continue
        record = _parse_record(line)
        if principal is not None and record.get('principal') != principal:
            continue
        if action is not None and record.get('action') != action:
            continue
        if result is not None and record.get('result') != result:
            continue
        if total >= offset and len(matches) < limit:
            matches.append(record)
        total += 1
    return matches, total
