import unittest
from vouch.hasher import Hasher
import pandas as pd
import numpy as np

class TestHasher(unittest.TestCase):
    def test_basic_types(self):
        self.assertEqual(Hasher.hash_object(1), Hasher.hash_object(1))
        self.assertNotEqual(Hasher.hash_object(1), Hasher.hash_object(2))
        self.assertEqual(Hasher.hash_object("foo"), Hasher.hash_object("foo"))
        self.assertEqual(Hasher.hash_object(None), Hasher.hash_object(None))

    def test_collections(self):
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1} # Order shouldn't matter for dicts
        self.assertEqual(Hasher.hash_object(d1), Hasher.hash_object(d2))

        l1 = [1, 2]
        l2 = [1, 2]
        self.assertEqual(Hasher.hash_object(l1), Hasher.hash_object(l2))

    def test_pandas(self):
        df1 = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
        df2 = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
        df3 = pd.DataFrame({"a": [1, 2], "b": [3, 5]})

        self.assertEqual(Hasher.hash_object(df1), Hasher.hash_object(df2))
        self.assertNotEqual(Hasher.hash_object(df1), Hasher.hash_object(df3))

    def test_numpy(self):
        arr1 = np.array([1, 2, 3])
        arr2 = np.array([1, 2, 3])
        arr3 = np.array([1, 2, 4])

        self.assertEqual(Hasher.hash_object(arr1), Hasher.hash_object(arr2))
        self.assertNotEqual(Hasher.hash_object(arr1), Hasher.hash_object(arr3))
