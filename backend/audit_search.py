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


def search_audit_records(
    *,
    principal: str | None = None,
    action: str | None = None,
    result: str | None = None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, str]], int]:
    path = security.AUDIT_LOG_PATH
    if not path.exists():
        return [], 0
    if not security.verify_audit_log(path):
        raise AuditLogIntegrityError('Audit log integrity check failed')

    matches: list[dict[str, str]] = []
    total = 0
    with path.open('r', encoding='utf-8') as handle:
        for raw_line in handle:
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
