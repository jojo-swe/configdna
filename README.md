# ConfigDNA

ConfigDNA fingerprints and semantically compares IOS-like network configurations.

Traditional line diffs are noisy: reordered sections, whitespace, generated metadata, and secret rotation can hide the changes that actually affect forwarding or security. ConfigDNA normalizes configuration structure, masks sensitive values, and reports risk-classified changes.

## What it does

- preserves parent/child configuration hierarchy
- ignores comments, whitespace noise, and selected volatile lines
- redacts passwords, secrets, SNMP communities, and pre-shared keys
- creates stable SHA-256 fingerprints
- compares configurations independent of section order
- classifies routing and security policy changes as high risk
- classifies interface and control-plane changes as medium risk
- emits human-readable or JSON output
- supports CI policy gates through exit codes

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

configdna fingerprint examples/before.cfg
configdna diff examples/before.cfg examples/after.cfg
```

Example output:

```text
Highest risk: high
- description WAN uplink [interface GigabitEthernet0/0] (medium: interface or control-plane behavior changed)
+ description ISP-A primary uplink [interface GigabitEthernet0/0] (medium: interface or control-plane behavior changed)
+ permit icmp any host 192.0.2.2 echo [ip access-list extended INTERNET-IN] (high: security or routing policy changed)
```

Structured output:

```bash
configdna diff examples/before.cfg examples/after.cfg --json
```

Fail a pipeline when medium- or high-risk drift is detected:

```bash
configdna diff intended.cfg running.cfg --fail-on-risk medium
```

Exit codes:

- `0`: comparison completed and policy threshold was not reached
- `1`: configured risk threshold was reached
- `2`: input could not be read

## Python API

```python
from configdna import compare, fingerprint

result = compare(intended_config, running_config)
print(result.highest_risk)
print(result.to_dict())

stable_id = fingerprint(running_config)
```

## Design

ConfigDNA converts each configuration into stable statements:

```text
interface GigabitEthernet0/0 :: description WAN uplink
router ospf 10 :: network 192.0.2.0 0.0.0.255 area 0
```

This makes parent context explicit and prevents commands from different interfaces, routing processes, or policy blocks from being treated as equivalent.

Secret values are normalized to `<redacted>`, so rotating a password does not leak credentials or create a false semantic change.

## Use cases

- pre- and post-change validation
- intended-versus-running configuration drift
- CI checks for infrastructure repositories
- sanitized incident-review evidence
- fleet configuration fingerprinting
- highlighting risky changes during peer review

## Development

```bash
ruff check .
pytest
```

## Scope

Version 0.2 focuses on Cisco IOS-like hierarchical text. Future adapters can provide vendor-specific parsing for IOS XR, NX-OS, Junos, EOS, and structured configuration formats.

## License

Apache License 2.0.
