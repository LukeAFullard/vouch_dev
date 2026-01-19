import vouch
import os

def function_a():
    import pandas as pd
    with open("data_a.csv", "w") as f: f.write("col1\n1\n")
    df = pd.read_csv("data_a.csv")
    return df

@vouch.record
def main():
    function_a()

if __name__ == "__main__":
    import glob
    for f in glob.glob("audit_*.vch"): os.remove(f)
    main()

    # Check log
    latest = max(glob.glob("audit_*.vch"), key=os.path.getctime)
    import zipfile, json
    with zipfile.ZipFile(latest, 'r') as z:
        log = json.loads(z.read("audit_log.json"))

    found = False
    for e in log:
        if "read_csv" in e.get("target", ""):
            found = True

    if found:
        print("SUCCESS: Inner import logged")
    else:
        print("FAILURE: Inner import NOT logged")

    os.remove("data_a.csv")
    os.remove(latest)
