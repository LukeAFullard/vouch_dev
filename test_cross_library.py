import vouch
import pandas as pd
import numpy as np

@vouch.record
def main():
    df = pd.DataFrame({'a': [1, 2, 3]})

    # 1. Cross-library return
    # to_numpy() returns a numpy array.
    # df is wrapped. to_numpy() is logged.
    # Result is numpy.ndarray.
    # Does Auditor wrap it?
    # Logic: pkg='pandas'. Result pkg='numpy'. NO match.
    arr = df.to_numpy()
    print(f"Array type: {type(arr)}") # Expected: <class 'numpy.ndarray'> (unwrapped)

    # Operations on arr are NOT logged
    # arr.mean() -> Call on unwrapped object
    m = arr.mean()

    # 2. Builtin return
    # to_dict() returns dict
    d = df.to_dict()
    print(f"Dict type: {type(d)}") # Expected: <class 'dict'>

if __name__ == "__main__":
    main()
