
import vouch
import unittest
import sys

# Define a mock library structure
class MockLib:
    class MyData:
        def __init__(self, value):
            self.value = value
        def get(self):
            return self.value

    class Index: # Valid non-pandas Index class
        def __init__(self, x):
            self.x = x

# Manually set module to simulate a real package
MockLib.MyData.__module__ = "mock_data_lib"
MockLib.Index.__module__ = "mock_data_lib"

class TestGenericSubclassing(unittest.TestCase):
    def test_dynamic_subclassing_generic(self):
        # Register a finder for mock_data_lib
        class MockFinder:
            def _should_audit(self, name): return name == "mock_data_lib"

        session = vouch.TraceSession("test_subclass.vch", strict=False, audit_classes=[])
        session.register_finder(MockFinder())

        # Wrap the library
        lib = vouch.auditor.Auditor(MockLib, name="mock_data_lib")

        with session:
            # 1. Test generic class
            obj = lib.MyData(42)
            self.assertTrue(isinstance(obj, MockLib.MyData), "MyData should be dynamically subclassed")
            self.assertEqual(obj.get(), 42)

            # 2. Test class named "Index" (should NOT be excluded because it's not pandas)
            idx = lib.Index(10)
            self.assertTrue(isinstance(idx, MockLib.Index), "Index (non-pandas) should be dynamically subclassed")

if __name__ == "__main__":
    unittest.main()
