import unittest
import os
import shutil
from unittest.mock import patch
from vouch.session import TraceSession

class TestFixVerification(unittest.TestCase):
    def test_broken_session_cleanup(self):
        """
        Test that if a session fails to initialize (e.g. strict mode check),
        the global context var is properly reset so subsequent sessions can run.
        """
        vch_file = "test_cleanup.vch"

        # 1. Trigger a failure in __enter__
        # We patch tempfile.mkdtemp to raise an exception.
        # This happens after _active_session.set(self)
        with patch("tempfile.mkdtemp", side_effect=RuntimeError("Boom")):
            try:
                with TraceSession(vch_file, strict=False):
                    pass
            except RuntimeError as e:
                self.assertEqual(str(e), "Boom")
            except AttributeError as e:
                self.fail(f"Regression: AttributeError in exception handler: {e}")

        # 2. Try to run a valid session
        # If the bug persists or cleanup wasn't done, this might fail
        try:
            with TraceSession(vch_file, strict=False) as sess:
                pass
        except RuntimeError as e:
            if "Nested TraceSessions" in str(e):
                self.fail("Regression: ContextVar not reset after initialization failure")
            raise
        finally:
            if os.path.exists(vch_file):
                os.remove(vch_file)

if __name__ == "__main__":
    unittest.main()
