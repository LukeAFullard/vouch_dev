import vouch
import pandas as pd
import os

# Create dummy data
with open("data_global.csv", "w") as f: f.write("col1\n1\n")

def function_using_global_pd():
    # Uses the global 'pd' variable
    df = pd.read_csv("data_global.csv")
    return df

@vouch.record
def main():
    print(f"Inside main, global pd type: {type(pd)}")
    function_using_global_pd()

if __name__ == "__main__":
    import glob
    for f in glob.glob("audit_*.vch"): os.remove(f)

    print(f"Before record, global pd type: {type(pd)}")
    main()
    print(f"After record, global pd type: {type(pd)}")

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
        print("SUCCESS: Global import usage logged")
    else:
        print("FAILURE: Global import usage NOT logged")

    os.remove("data_global.csv")
    os.remove(latest)
