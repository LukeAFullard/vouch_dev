import vouch
import pandas as pd
import sys

def check_wrapping():
    print(f"Global pd type: {type(pd)}")
    print(f"sys.modules['pandas'] type: {type(sys.modules['pandas'])}")

@vouch.record
def main():
    print("Inside main:")
    check_wrapping()

    # Re-import to get the wrapped version
    import pandas as pd2
    print(f"Local import pd2 type: {type(pd2)}")

if __name__ == "__main__":
    main()
