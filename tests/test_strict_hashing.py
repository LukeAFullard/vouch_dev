import vouch
import unittest

class UnstableObj:
    def __init__(self):
        pass
    # No __repr__ override, so it uses <object at ...>
    # No __dict__ or empty dict

class TestStrictHashing(unittest.TestCase):
    def test_strict_mode_unstable_hash(self):
        # Create an object that will trigger unstable hash warning/error
        # We need an object that has default repr with address and fails fallback.
        # object() is perfect.

        with self.assertRaises(ValueError) as cm:
            with vouch.start(strict=True, allow_ephemeral=True) as sess:
                # We need to trigger logging.
                # vouch.annotate logs arguments.
                sess.annotate("unstable", object())

        self.assertIn("Unstable hash", str(cm.exception))

    def test_normal_mode_unstable_hash(self):
        # Should not raise
        with vouch.start(strict=False, allow_ephemeral=True) as sess:
            sess.annotate("unstable", object())

if __name__ == "__main__":
    unittest.main()
