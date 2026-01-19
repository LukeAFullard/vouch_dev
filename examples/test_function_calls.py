import vouch
import pandas as pd
import os

# Create dummy data
with open("data_a.csv", "w") as f: f.write("col1,col2\n1,2\n")
with open("data_b.csv", "w") as f: f.write("col3,col4\n3,4\n")

def function_a():
    print("Executing function_a")
    # This library call should be logged
    df = pd.read_csv("data_a.csv")
    return df

def function_b():
    print("Executing function_b")
    # This library call should be logged
    df = pd.read_csv("data_b.csv")
    return df

@vouch.record
def main():
    print("Starting main")
    function_a()
    function_b()
    print("Finished main")

if __name__ == "__main__":
    # Clean up old audit
    import glob
    for f in glob.glob("audit_*.vch"): os.remove(f)

    main()

    # Inspect the log
    latest_file = max(glob.glob("audit_*.vch"), key=os.path.getctime)
    print(f"Inspecting {latest_file}...")

    import zipfile
    import json

    with zipfile.ZipFile(latest_file, 'r') as z:
        log = json.loads(z.read("audit_log.json"))

    for entry in log:
        if entry.get("op") == "call":
            print(f"Log Entry: {entry.get('target')}")

    # Clean up
    os.remove("data_a.csv")
    os.remove("data_b.csv")
    os.remove(latest_file)
