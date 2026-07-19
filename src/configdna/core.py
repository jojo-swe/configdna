"""Semantic normalization and comparison of network configurations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

_VOLATILE_PATTERNS = (
    re.compile(r"^! Last configuration change", re.I),
    re.compile(r"^ntp clock-period ", re.I),
    re.compile(r"^Building configuration", re.I),
    re.compile(r"^Current configuration", re.I),
)
_SECRET_PATTERNS = (
    re.compile(r"^(enable (?:password|secret)(?: \d+)? )(.+)$", re.I),
    re.compile(r"^(username \S+ (?:password|secret)(?: \d+)? )(.+)$", re.I),
    re.compile(r"^(snmp-server community )(.+?)(\s+(?:ro|rw).*)?$", re.I),
    re.compile(r"^(pre-shared-key(?: local| remote)? )(.+)$", re.I),
)
_HIGH_RISK = ("ip access-list", "access-list", "router bgp", "router ospf", "ip route", "crypto ", "aaa ")
_MEDIUM_RISK = ("interface ", "vlan ", "router ", "line vty")


@dataclass(frozen=True, slots=True)
class Statement:
    section: str
    command: str

    @property
    def key(self) -> str:
        return f"{self.section} :: {self.command}" if self.section else self.command


@dataclass(frozen=True, slots=True)
class Change:
    kind: str
    section: str
    command: str
    risk: str
    reason: str


@dataclass(slots=True)
class Comparison:
    before_fingerprint: str
    after_fingerprint: str
    changes: list[Change] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    @property
    def highest_risk(self) -> str:
        order = {"none": 0, "low": 1, "medium": 2, "high": 3}
        return max((change.risk for change in self.changes), key=order.get, default="none")

    def to_dict(self) -> dict[str, object]:
        return {
            "changed": self.changed,
            "highest_risk": self.highest_risk,
            "before_fingerprint": self.before_fingerprint,
            "after_fingerprint": self.after_fingerprint,
            "summary": {
                "total": len(self.changes),
                "added": sum(change.kind == "added" for change in self.changes),
                "removed": sum(change.kind == "removed" for change in self.changes),
            },
            "changes": [asdict(change) for change in self.changes],
        }


def _redact(line: str) -> str:
    for pattern in _SECRET_PATTERNS:
        match = pattern.match(line)
        if match:
            groups = match.groups()
            if len(groups) == 2:
                return f"{groups[0]}<redacted>"
            return f"{groups[0]}<redacted>{groups[2] or ''}"
    return line


def normalize(config: str) -> list[Statement]:
    """Convert IOS-like text into stable hierarchical statements."""
    statements: list[Statement] = []
    section = ""
    for raw in config.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        stripped = " ".join(raw.strip().split())
        if any(pattern.search(stripped) for pattern in _VOLATILE_PATTERNS):
            continue
        if raw[:1].isspace():
            statements.append(Statement(section, _redact(stripped)))
            continue
        section = _redact(stripped)
        statements.append(Statement("", section))
    return sorted(set(statements), key=lambda item: (item.section, item.command))


def fingerprint(config: str) -> str:
    payload = "\n".join(statement.key for statement in normalize(config))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _risk(statement: Statement) -> tuple[str, str]:
    text = statement.section or statement.command
    lowered = text.lower()
    if any(lowered.startswith(prefix) for prefix in _HIGH_RISK):
        return "high", "security or routing policy changed"
    if any(lowered.startswith(prefix) for prefix in _MEDIUM_RISK):
        return "medium", "interface or control-plane behavior changed"
    return "low", "general configuration changed"


def compare(before: str, after: str) -> Comparison:
    before_set = set(normalize(before))
    after_set = set(normalize(after))
    changes: list[Change] = []
    for kind, statements in (("removed", before_set - after_set), ("added", after_set - before_set)):
        for statement in sorted(statements, key=lambda item: item.key):
            risk, reason = _risk(statement)
            changes.append(Change(kind, statement.section, statement.command, risk, reason))
    return Comparison(fingerprint(before), fingerprint(after), changes)
