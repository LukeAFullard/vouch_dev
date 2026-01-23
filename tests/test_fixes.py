import pytest
import pandas as pd
import numpy as np
import vouch
from vouch.auditor import Auditor
import os

# No global setup needed

def test_cross_module_imports():
    # Limitation 1 fix verification using standard library (json) to avoid deps

    # Rewrite dummy_utils to use json
    with open("tests/dummy_utils_json.py", "w") as f:
        f.write("import json\n")
        f.write("def parse(s):\n")
        f.write("    return json.loads(s)\n")

    import tests.dummy_utils_json as dummy_json

    try:
        with vouch.start(filename="test_fixes.vch", allow_ephemeral=True, targets=["json"]):
            # Check if json module in dummy_json is wrapped
            # This is the core verification: did we patch the global in that module?
            assert isinstance(dummy_json.json, Auditor), "Cross-module import (json) should be patched"

            res = dummy_json.parse('{"a": 1}')

            # Result (dict) is not wrapped because it's a builtin, but correctness is checked
            assert res == {"a": 1}

    finally:
        if os.path.exists("tests/dummy_utils_json.py"):
            os.remove("tests/dummy_utils_json.py")

def test_cross_library_returns():
    # Limitation 2 fix verification
    with vouch.start(filename="test_fixes.vch", allow_ephemeral=True):
        # Create a wrapped dataframe via concat (workaround for constructor limitation)
        df_raw = pd.DataFrame({'a': [1, 2]})
        df = pd.concat([df_raw])
        assert isinstance(df, Auditor), "Dataframe should be wrapped"

        # to_numpy returns numpy array. Should be wrapped.
        arr = df.to_numpy()
        assert isinstance(arr, Auditor), "Cross-library return (numpy) should be wrapped"

def test_operator_overloading():
    # Limitation 4 fix verification
    with vouch.start(filename="test_fixes.vch", allow_ephemeral=True):
        df_raw = pd.DataFrame({'a': [1, 2], 'b': [3, 4]})
        df = pd.concat([df_raw])

        # Matrix multiplication @
        res = df @ df.T
        assert isinstance(res, Auditor), "Operator overloading result should be wrapped"

        # Addition
        res2 = df + df
        assert isinstance(res2, Auditor), "Addition result should be wrapped"

        # Comparison
        res3 = df == df
        assert isinstance(res3, Auditor), "Comparison result should be wrapped"

@pytest.fixture(scope="session", autouse=True)
def cleanup():
    yield
    if os.path.exists("test_fixes.vch"):
        os.remove("test_fixes.vch")
    if os.path.exists("tests/dummy_utils.py"):
        os.remove("tests/dummy_utils.py")
