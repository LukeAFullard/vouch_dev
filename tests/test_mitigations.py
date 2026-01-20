import unittest
import os
import shutil
import json
import sys
from vouch.hasher import Hasher
from vouch.importer import auto_audit, VouchFinder
from vouch.auditor import Auditor

# 1. Test Custom Hashing Protocol
class CustomObj:
    def __init__(self, val):
        self.val = val

    def __vouch_hash__(self):
        return f"HASH:{self.val}"

# 2. Test Custom Registry
class ExternalObj:
    def __init__(self, val):
        self.val = val

def external_hasher(obj):
    return f"EXT:{obj.val}"

class TestMitigations(unittest.TestCase):
    def test_protocol_hashing(self):
        obj = CustomObj(42)
        h = Hasher.hash_object(obj)
        self.assertEqual(h, "HASH:42")

    def test_registry_hashing(self):
        Hasher.register(ExternalObj, external_hasher)
        obj = ExternalObj(99)
        h = Hasher.hash_object(obj)
        self.assertEqual(h, "EXT:99")

    def test_importer_excludes(self):
        # We need to simulate a module that would be audited if not excluded
        # Let's use 'json' as a target but exclude it.
        # json is stdlib, so it might be tricky since stdlib is usually excluded.
        # Let's create a fake module in sys.modules

        module_name = "fake_module_for_test"
        exclude_name = "fake_exclude_for_test"

        # Create dummy modules
        sys.modules[module_name] = type(sys)(module_name)
        sys.modules[exclude_name] = type(sys)(exclude_name)

        try:
            # Case 1: Wildcard audit, check if 'excludes' prevents wrapping
            with auto_audit(targets=["*"], excludes=[exclude_name]):
                # 'fake_module_for_test' should be wrapped
                # 'fake_exclude_for_test' should NOT be wrapped

                # Note: auto_audit wraps existing modules in sys.modules
                self.assertIsInstance(sys.modules[module_name], Auditor)
                self.assertNotIsInstance(sys.modules[exclude_name], Auditor)

        finally:
            # Cleanup
            if module_name in sys.modules:
                del sys.modules[module_name]
            if exclude_name in sys.modules:
                del sys.modules[exclude_name]

if __name__ == "__main__":
    unittest.main()
