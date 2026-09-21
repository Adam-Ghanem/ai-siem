from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
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


@contextmanager
def _verified_audit_lines() -> Iterator[Iterator[str]]:
    """Yield an integrity-verified, locked stream of audit-log lines.

    Verification and iteration share the same in-process and file locks used by
    audit writers. Keeping those locks for the lifetime of the iterator prevents
    a valid log from changing between verification and search, while streaming
    avoids materializing the complete audit history in memory.
    """
    path = security.AUDIT_LOG_PATH
    with security._AUDIT_LOCK:
        with security._audit_file_lock(path):
            if not path.exists():
                yield iter(())
                return
            valid, _ = security._audit_chain_state(path)
            if not valid:
                raise AuditLogIntegrityError('Audit log integrity check failed')
            with path.open('r', encoding='utf-8') as handle:
                yield handle


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
    with _verified_audit_lines() as audit_lines:
        for raw_line in audit_lines:
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
