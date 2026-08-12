from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthContext:
    principal_id: str
    tenant_id: str
    roles: frozenset[str]

    def has_any_role(self, *required: str) -> bool:
        return bool(self.roles.intersection(required))

    def to_dict(self) -> dict[str, object]:
        return {
            'principal_id': self.principal_id,
            'tenant_id': self.tenant_id,
            'roles': sorted(self.roles),
        }
