import vouch
import module_b # Imports pandas inside module_b
import pandas as pd

@vouch.record
def main():
    print("Main start")
    # This should be wrapped because main's globals are patched
    print(f"Main pd type: {type(pd)}")

    # This calls a function in another module.
    # That module's globals were initialized at import time.
    # _patch_caller_globals only patches the *calling* frame (main's module).
    # It likely does NOT iterate over all loaded modules to patch their globals.
    module_b.use_pandas_in_b()

if __name__ == "__main__":
    main()
