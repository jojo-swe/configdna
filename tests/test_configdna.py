from configdna import compare, fingerprint, normalize


BASE = """
hostname edge-r1
!
interface GigabitEthernet0/0
 description WAN uplink
 ip address 192.0.2.2 255.255.255.0
 no shutdown
!
router ospf 10
 network 192.0.2.0 0.0.0.255 area 0
!
enable secret 9 old-secret
"""


def test_fingerprint_ignores_formatting_and_secret_value() -> None:
    equivalent = """
hostname   edge-r1
interface GigabitEthernet0/0
  description WAN uplink
  ip address 192.0.2.2 255.255.255.0
  no shutdown
enable secret 9 new-secret
router ospf 10
  network 192.0.2.0 0.0.0.255 area 0
"""
    assert fingerprint(BASE) == fingerprint(equivalent)


def test_normalization_preserves_hierarchy_and_redacts_secrets() -> None:
    statements = normalize(BASE)
    keys = {statement.key for statement in statements}
    assert "interface GigabitEthernet0/0 :: description WAN uplink" in keys
    assert "enable secret 9 <redacted>" in keys
    assert all("old-secret" not in key for key in keys)


def test_compare_classifies_routing_and_interface_changes() -> None:
    after = BASE.replace(
        "network 192.0.2.0 0.0.0.255 area 0",
        "network 198.51.100.0 0.0.0.255 area 0",
    ).replace("description WAN uplink", "description ISP-A")
    result = compare(BASE, after)
    assert result.changed
    assert result.highest_risk == "high"
    assert any(change.section == "router ospf 10" for change in result.changes)
    assert any(change.section == "interface GigabitEthernet0/0" for change in result.changes)


def test_reordered_sections_do_not_create_false_changes() -> None:
    reordered = "\n".join(reversed(BASE.splitlines()))
    # Reversing child lines changes hierarchy, so use an actually reordered valid config.
    reordered = """
enable secret 9 another-value
router ospf 10
 network 192.0.2.0 0.0.0.255 area 0
interface GigabitEthernet0/0
 no shutdown
 ip address 192.0.2.2 255.255.255.0
 description WAN uplink
hostname edge-r1
"""
    assert not compare(BASE, reordered).changed
