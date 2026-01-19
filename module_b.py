# module_b.py
import pandas as pd # Imported early

def use_pandas_in_b():
    print(f"Module B pd type: {type(pd)}")
    return pd.DataFrame({'b': [1]})
