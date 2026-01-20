import logging
from vouch.hasher import Hasher

class UnstableObj:
    pass

def test_hasher_warning(caplog):
    obj = UnstableObj()
    with caplog.at_level(logging.WARNING):
        Hasher.hash_object(obj)

    assert "Unstable hash" in caplog.text
    assert "UnstableObj" in caplog.text

if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
