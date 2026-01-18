import unittest
from vouch.auditor import Auditor
from vouch.session import TraceSession
import os
import shutil

class MockTarget:
    def foo(self, x):
        return x + 1

    def bar(self, y):
        return y * 2

class TestAuditor(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_auditor_output"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_interception(self):
        target = MockTarget()
        wrapped = Auditor(target, name="target")

        vch_path = os.path.join(self.test_dir, "test.vch")

        with TraceSession(vch_path, strict=False):
            res = wrapped.foo(10)
            self.assertEqual(res, 11)

        # Check if log was created (indirectly)
        # Detailed log content check is done in integration tests
        self.assertTrue(os.path.exists(vch_path))
