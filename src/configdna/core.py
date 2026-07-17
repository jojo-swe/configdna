from __future__ import annotations
import hashlib
import re

def normalize(config: str) -> str:
    lines=[]
    for line in config.splitlines():
        compact=re.sub(r"\s+"," ",line.strip())
        if compact and not compact.startswith("!"):
            lines.append(compact)
    return "\n".join(lines)

def fingerprint(config: str) -> str:
    return hashlib.sha256(normalize(config).encode()).hexdigest()
