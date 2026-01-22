import unittest
from unittest.mock import MagicMock, patch
from vouch.hasher import Hasher
import hashlib
import json

class TestAuditCorrectness(unittest.TestCase):

    def test_hasher_with_dict_return(self):
        """Test that objects returning a dict from __vouch_hash__ result in a string hash."""
        class CustomObj:
            def __vouch_hash__(self):
                return {"a": 1, "b": 2}

        obj = CustomObj()
        # Should return a string (hash), not the dict itself
        res = Hasher.hash_object(obj)
        self.assertIsInstance(res, str)

        # Verify it matches the hash of the dict
        expected = Hasher.hash_object({"a": 1, "b": 2})
        self.assertEqual(res, expected)

    def test_hasher_recursion_limit(self):
        """Test that Hasher handles cycles in __vouch_hash__ gracefully."""
        class RecursiveObj:
            def __vouch_hash__(self):
                return self # Infinite recursion

        obj = RecursiveObj()
        # Hasher catches RecursionError and returns "HASH_FAILED" (or similar)
        # It should NOT crash.
        res = Hasher.hash_object(obj, raise_error=True)
        self.assertEqual(res, "HASH_FAILED")

if __name__ == '__main__':
    unittest.main()
