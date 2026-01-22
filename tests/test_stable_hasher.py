import unittest
import pandas as pd
import numpy as np
from vouch.hasher import Hasher

class Unstable:
    pass

class Recursive:
    pass

class TestStableHasher(unittest.TestCase):
    def test_unstable_dict_hashing(self):
        obj1 = Unstable()
        obj2 = Unstable()

        # Ensure they have different addresses (and thus different default reprs)
        self.assertNotEqual(str(obj1), str(obj2))

        data1 = {"key": obj1}
        data2 = {"key": obj2}

        hash1 = Hasher.hash_object(data1)
        hash2 = Hasher.hash_object(data2)

        self.assertEqual(hash1, hash2, "Hashes should be stable for identical structure despite unstable addresses")
        self.assertNotEqual(hash1, "HASH_FAILED")
        self.assertNotEqual(hash1, "HASH_FAILED_DICT")

    def test_recursive_object_hashing(self):
        obj1 = Recursive()
        obj1.cycle = obj1

        obj2 = Recursive()
        obj2.cycle = obj2

        hash1 = Hasher.hash_object(obj1)
        hash2 = Hasher.hash_object(obj2)

        self.assertEqual(hash1, hash2, "Hashes should be stable for recursive objects")
        self.assertNotEqual(hash1, "HASH_FAILED")
        self.assertNotEqual(hash1, "HASH_FAILED_DICT")

    def test_nested_dataframe_hashing(self):
        df1 = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
        df2 = pd.DataFrame({"a": [1, 2], "b": [3, 4]})

        data1 = {"df": df1}
        data2 = {"df": df2}

        hash1 = Hasher.hash_object(data1)
        hash2 = Hasher.hash_object(data2)

        self.assertEqual(hash1, hash2)

        # Ensure it's not just hashing the string repr
        # If we change data but keep shape/repr same (unlikely for small df, but theoretically)
        df3 = pd.DataFrame({"a": [1, 2], "b": [3, 5]})
        hash3 = Hasher.hash_object({"df": df3})

        self.assertNotEqual(hash1, hash3)

    def test_numpy_array_hashing(self):
        arr1 = np.array([1, 2, 3])
        arr2 = np.array([1, 2, 3])

        hash1 = Hasher.hash_object({"arr": arr1})
        hash2 = Hasher.hash_object({"arr": arr2})

        self.assertEqual(hash1, hash2)

        arr3 = np.array([1, 2, 4])
        hash3 = Hasher.hash_object({"arr": arr3})

        self.assertNotEqual(hash1, hash3)

    def test_pure_recursion_error(self):
        # A pure dict cycle (no custom objects)
        d = {}
        d['self'] = d

        # This triggers RecursionError in json.dump(check_circular=False)
        # Hasher catches it and falls back to manual repr string hashing.
        # Python's repr handles recursion safely (prints "{...}"), so this succeeds.

        hash_val = Hasher.hash_object(d)
        self.assertNotEqual(hash_val, "HASH_FAILED_DICT")
        self.assertNotEqual(hash_val, "HASH_FAILED")
        self.assertTrue(len(hash_val) == 64) # SHA256 length

if __name__ == '__main__':
    unittest.main()
