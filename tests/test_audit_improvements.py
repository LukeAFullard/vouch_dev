import pytest
import asyncio
import vouch
import pandas as pd
import numpy as np
from vouch.auditor import Auditor
import sys

def test_async_wrapping():
    class MockLib:
        async def get_data(self):
            return np.array([1, 2, 3])

    mock = MockLib()
    wrapped = Auditor(mock, name="mock")

    # Needs active session to trigger cross-library wrapping (MockLib != numpy)
    with vouch.start(targets=["numpy"], filename="test_async.vch"):
        coro = wrapped.get_data()
        res = asyncio.run(coro)

        assert isinstance(res, Auditor), "Async result should be wrapped"
        # Unwrap for value check
        assert (res._target == np.array([1, 2, 3])).all()

def test_generator_wrapping():
    class MockLib:
        def get_gen(self):
            yield np.array([1])
            yield np.array([2])

    mock = MockLib()
    wrapped = Auditor(mock, name="mock")

    # Needs active session
    with vouch.start(targets=["numpy"], filename="test_gen.vch"):
        gen = wrapped.get_gen()
        items = list(gen)

        assert len(items) == 2
        assert isinstance(items[0], Auditor), "Generator item should be wrapped"
        assert items[0]._target[0] == 1

def test_constructor_interception():
    # Verify pd.DataFrame() returns a wrapped object
    # Default targets include pandas
    with vouch.start(filename="test_constructor.vch"):
        # We need to ensure we are calling the Auditor wrapper of pandas
        # In this test file, 'pd' is imported at top level.
        # 'vouch.start' patches globals of this module.
        # So 'pd' should become wrapped inside this block?
        # Wait, 'vouch.start' calls 'auto_audit'.
        # 'auto_audit' calls '_patch_loaded_modules'.
        # It patches modules in sys.modules.
        # Does it patch the LOCAL variables of the test function? NO.
        # Does it patch the GLOBAL variables of the test module? YES, via _patch_loaded_modules or _patch_caller_globals.

        # NOTE: pytest runs tests in a way where globals might be tricky.
        # But 'pd' is global in this file.

        print(f"DEBUG: pd type inside test: {type(pd)}")

        df = pd.DataFrame({'a': [1]})
        print(f"DEBUG: df type: {type(df)}")
        assert isinstance(df, Auditor), "DataFrame constructor result should be wrapped"

def test_stdlib_optin():
    import json
    # Explicitly target json
    with vouch.start(targets=["json"], filename="test_stdlib.vch"):
        # Import inside to ensure we get it from sys.modules
        import json as local_json
        print(f"DEBUG: local_json type: {type(local_json)}")
        assert isinstance(local_json, Auditor), "Explicitly targeted stdlib module should be wrapped"
