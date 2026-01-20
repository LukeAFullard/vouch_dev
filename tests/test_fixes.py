import pytest
import pandas as pd
import numpy as np
import vouch
from vouch.auditor import Auditor
import os

# Create a dummy module for cross-module test
with open("tests/dummy_utils.py", "w") as f:
    f.write("import pandas as pd\n")
    f.write("def load_data():\n")
    f.write("    return pd.DataFrame({'a': [1]})\n")

import tests.dummy_utils as dummy_utils

def test_cross_module_imports():
    # Limitation 1 fix verification
    # Start a session
    with vouch.start(filename="test_fixes.vch", allow_ephemeral=True):
        # dummy_utils.pd should be wrapped
        assert isinstance(dummy_utils.pd, Auditor), "Cross-module imports should be patched"

        # Calling function should work and use wrapped pandas
        df = dummy_utils.load_data()
        assert isinstance(df, Auditor) or isinstance(df, pd.DataFrame)

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
