from configdna import fingerprint, normalize

def test_fingerprint_is_whitespace_stable() -> None:
    assert fingerprint("interface  Gi0/1") == fingerprint("interface Gi0/1")

def test_comments_are_ignored() -> None:
    assert normalize("! generated\nhostname edge") == "hostname edge"
