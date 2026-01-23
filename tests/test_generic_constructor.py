import unittest
import vouch
from vouch.auditor import AuditorMixin
import tests.fake_lib as fake_lib
import sys

class TestGenericConstructor(unittest.TestCase):
    def test_generic_audit(self):
        # We target our fake_lib
        # We audit "Widget" class

        # NOTE: targets must use full module name as imported
        with vouch.start(targets=["tests.fake_lib"], audit_classes=["Widget"], strict=False):
            # Debug what fake_lib is
            print(f"fake_lib type: {type(fake_lib)}")

            # Avoid accessing attributes that trigger string conversion of target if target is module?
            # Module string repr should be fine.

            # 1. Constructor
            try:
                w = fake_lib.Widget("foo", 100)
            except RecursionError:
                print("Recursion detected!")
                raise

            # Check wrapping
            self.assertTrue(isinstance(w, AuditorMixin), "Widget should be wrapped")
            self.assertTrue(isinstance(w, fake_lib.Widget), "Isinstance check should pass")

            # Check behavior
            self.assertEqual(w.name, "foo")
            self.assertEqual(w.run(), "foo running")

if __name__ == "__main__":
    unittest.main()
