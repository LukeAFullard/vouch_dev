import unittest
from vouch.auditor import Auditor
from vouch.session import TraceSession
import os
import shutil

class Mutable:
    def __init__(self, val):
        self.val = val

    def __iadd__(self, other):
        self.val += other
        return self

    def __repr__(self):
        return f"Mutable({self.val})"

class TestAuditorOperators(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_auditor_ops_output"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_inplace_semantics_mutable(self):
        # Test custom mutable object with explicit __iadd__
        m = Mutable(10)
        w = Auditor(m)

        # We need a session to prevent errors during logging
        vch_path = os.path.join(self.test_dir, "test.vch")
        with TraceSession(vch_path, strict=False):
            w += 5

        self.assertEqual(w.val, 15)
        self.assertIs(w._target, m) # Wraps same object
        self.assertEqual(m.val, 15) # Original modified

    def test_inplace_semantics_list(self):
        # Test standard list
        l = [1, 2]
        w = Auditor(l)

        vch_path = os.path.join(self.test_dir, "test_list.vch")
        with TraceSession(vch_path, strict=False):
            w += [3]

        self.assertEqual(w._target, [1, 2, 3])
        self.assertIs(w._target, l) # Wraps same list

    def test_inplace_semantics_immutable(self):
        # Test integer (immutable)
        w = Auditor(10)
        old_w = w

        vch_path = os.path.join(self.test_dir, "test_int.vch")
        with TraceSession(vch_path, strict=False):
            w += 5

        self.assertEqual(w._target, 15)
        self.assertEqual(old_w._target, 10) # Old wrapper untouched
        self.assertIsNot(w, old_w) # New wrapper created

    def test_missing_ops(self):
        vch_path = os.path.join(self.test_dir, "test_ops.vch")
        with TraceSession(vch_path, strict=False):
            # Mod
            w = Auditor(10)
            res = w % 3
            self.assertEqual(res._target, 1)

            # Bitwise
            w = Auditor(5) # 101
            res = w << 1
            self.assertEqual(res._target, 10) # 1010

            res = w & 1
            self.assertEqual(res._target, 1)

if __name__ == "__main__":
    unittest.main()
