import logging
from vouch.hasher import Hasher

def test_hasher_warning(caplog):
    # Use object() which has no __dict__ and a memory address in repr()
    obj = object()
    with caplog.at_level(logging.WARNING):
        Hasher.hash_object(obj)

    assert "Unstable hash" in caplog.text
    # assert "UnstableObj" in caplog.text # The class name will be object
    assert "object" in caplog.text

if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
