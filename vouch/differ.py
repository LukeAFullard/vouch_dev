import os
import json
import zipfile
import tempfile
import difflib

class Differ:
    @staticmethod
    def diff_sessions(file1, file2, show_hashes=False):
        """
        Compares two Vouch sessions.
        """
        print(f"Comparing {file1} vs {file2}...")

        with tempfile.TemporaryDirectory() as temp1, tempfile.TemporaryDirectory() as temp2:
            try:
                Differ._safe_extract(file1, temp1)
                Differ._safe_extract(file2, temp2)
            except Exception as e:
                print(f"Error opening files: {e}")
                return

            print("\n--- Environment Comparison ---")
            Differ._diff_json(
                os.path.join(temp1, "environment.lock"),
                os.path.join(temp2, "environment.lock"),
                "Environment"
            )

            print("\n--- Audit Log Comparison ---")
            # For logs, we might want to compare length and operations
            Differ._diff_logs(
                os.path.join(temp1, "audit_log.json"),
                os.path.join(temp2, "audit_log.json")
            )

            print("\n--- Artifacts Comparison ---")
            Differ._diff_artifacts(
                os.path.join(temp1, "artifacts.json"),
                os.path.join(temp2, "artifacts.json"),
                show_hashes
            )

    @staticmethod
    def _safe_extract(zip_path, target_dir):
        with zipfile.ZipFile(zip_path, 'r') as z:
            # Safe extraction (Zip Slip protection)
            for member in z.infolist():
                name = member.filename
                if name.startswith('/') or '..' in name:
                    continue

                target_path = os.path.join(target_dir, name)
                try:
                    if os.path.commonpath([os.path.abspath(target_path), os.path.abspath(target_dir)]) != os.path.abspath(target_dir):
                        continue
                except ValueError:
                    continue

                z.extract(member, target_dir)

    @staticmethod
    def _diff_json(path1, path2, label):
        if not os.path.exists(path1) or not os.path.exists(path2):
            print(f"Missing {label} in one or both files.")
            return

        with open(path1, 'r') as f1, open(path2, 'r') as f2:
            j1 = json.load(f1)
            j2 = json.load(f2)

        # Simple key-value comparison
        keys = set(j1.keys()) | set(j2.keys())
        diff_found = False
        for k in sorted(keys):
            val1 = j1.get(k, "N/A")
            val2 = j2.get(k, "N/A")
            # Convert to string for display if needed
            if val1 != val2:
                print(f"Difference in {k}:")
                print(f"  < {val1}")
                print(f"  > {val2}")
                diff_found = True

        if not diff_found:
            print(f"{label} matches.")

    @staticmethod
    def _read_logs(path):
        """Reads logs from JSON array or NDJSON."""
        try:
            with open(path, 'r') as f:
                first = f.read(1)

            with open(path, 'r') as f:
                if first == '[':
                    return json.load(f)
                else:
                    return [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading log {path}: {e}")
            return []

    @staticmethod
    def _diff_logs(path1, path2):
         if not os.path.exists(path1) or not os.path.exists(path2):
            print("Missing audit_log.json.")
            return

         l1 = Differ._read_logs(path1)
         l2 = Differ._read_logs(path2)

         print(f"Log 1 entries: {len(l1)}")
         print(f"Log 2 entries: {len(l2)}")

         # Compare operations
         min_len = min(len(l1), len(l2))
         mismatch_count = 0
         for i in range(min_len):
             act1 = l1[i].get("action", "unknown")
             act2 = l2[i].get("action", "unknown")
             target1 = l1[i].get("target", "")
             target2 = l2[i].get("target", "")

             if act1 != act2 or target1 != target2:
                 print(f"Mismatch at entry {i}:")
                 print(f"  < {act1} {target1}")
                 print(f"  > {act2} {target2}")
                 mismatch_count += 1
                 if mismatch_count >= 5:
                     print("... (more mismatches suppressed)")
                     break

         if len(l1) != len(l2):
             print("Logs have different lengths.")
         elif min_len > 0:
             # Check exact equality if no mismatches found yet
             if l1 == l2:
                 print("Logs are identical.")
             else:
                 if mismatch_count == 0:
                     print("Logs have identical structure but content differences (timestamps/hashes).")

    @staticmethod
    def _diff_artifacts(path1, path2, show_hashes):
        if not os.path.exists(path1) or not os.path.exists(path2):
            # It's possible for artifacts.json to be missing if no artifacts were captured
            # Check if one exists
            exists1 = os.path.exists(path1)
            exists2 = os.path.exists(path2)
            if not exists1 and not exists2:
                print("No artifacts captured in either session.")
                return

            if exists1:
                print("Artifacts manifest present in file 1 but missing in file 2.")
            else:
                print("Artifacts manifest present in file 2 but missing in file 1.")
            return

        with open(path1, 'r') as f1, open(path2, 'r') as f2:
            a1 = json.load(f1)
            a2 = json.load(f2)

        all_files = set(a1.keys()) | set(a2.keys())
        diff_found = False

        for f in sorted(all_files):
            h1 = a1.get(f, "MISSING")
            h2 = a2.get(f, "MISSING")

            if h1 != h2:
                print(f"Artifact mismatch: {f}")
                if show_hashes:
                    print(f"  < {h1}")
                    print(f"  > {h2}")
                diff_found = True

        if not diff_found:
            print("Artifacts match.")
