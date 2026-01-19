import argparse
import sys
import os
import zipfile
import tempfile
import shutil
import json
import vouch
from .crypto import CryptoManager
from .hasher import Hasher
from .reporter import Reporter
from .differ import Differ
from .inspector import InspectorShell

def verify(args):
    filepath = args.file
    data_file = args.data

    if not os.path.exists(filepath):
        print(f"Error: File {filepath} not found.")
        sys.exit(1)

    print(f"Verifying {filepath}...")

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                z.extractall(temp_dir)
        except zipfile.BadZipFile:
            print("Error: Invalid Vouch file (not a zip).")
            sys.exit(1)

        # Check components
        required = ["audit_log.json", "signature.sig", "public_key.pem", "environment.lock"]
        for f in required:
            if not os.path.exists(os.path.join(temp_dir, f)):
                print(f"Error: Corrupt package. Missing {f}.")
                sys.exit(1)

        # Verify Signature
        try:
            pub_key = CryptoManager.load_public_key(os.path.join(temp_dir, "public_key.pem"))
            with open(os.path.join(temp_dir, "signature.sig"), "rb") as f:
                signature = f.read()

            CryptoManager.verify_file(pub_key, os.path.join(temp_dir, "audit_log.json"), signature)
            print("  [OK] Signature Verification: Valid")
            print("  [OK] Log Integrity: Valid")
        except Exception as e:
            print(f"  [FAIL] Signature Verification: Invalid ({e})")
            sys.exit(1)

        # Verify Timestamp (RFC 3161)
        tsr_path = os.path.join(temp_dir, "audit_log.tsr")
        if os.path.exists(tsr_path):
            print("  [...] Verifying Timestamp...")
            from .timestamp import TimestampClient
            client = TimestampClient()
            try:
                # Basic verification of data match
                if client.verify_timestamp(os.path.join(temp_dir, "audit_log.json"), tsr_path):
                    print("    [OK] Timestamp Verified (Matches Log)")
                else:
                    print("    [FAIL] Timestamp Verification Failed")
            except Exception as e:
                print(f"    [FAIL] Timestamp Error: {e}")

        # Verify Log Chain
        try:
            with open(os.path.join(temp_dir, "audit_log.json"), "r") as f:
                log_data = json.load(f)

            print("  [...] Verifying log chain integrity...")
            prev_hash = "0" * 64
            expected_seq = 1
            chain_valid = True

            for i, entry in enumerate(log_data):
                # Check sequence number if present (backward compatibility)
                if "sequence_number" in entry:
                    if entry["sequence_number"] != expected_seq:
                        print(f"    [FAIL] Entry {i}: Sequence mismatch (expected {expected_seq}, got {entry['sequence_number']})")
                        chain_valid = False
                    expected_seq += 1

                # Check previous hash if present
                if "previous_entry_hash" in entry:
                    if entry["previous_entry_hash"] != prev_hash:
                        print(f"    [FAIL] Entry {i}: Previous hash mismatch")
                        chain_valid = False

                prev_hash = Hasher.hash_object(entry)

            if chain_valid:
                 print("  [OK] Log Chain Integrity: Valid")
            else:
                 print("  [FAIL] Log Chain Integrity: Broken")
                 sys.exit(1)
        except Exception as e:
            print(f"  [WARN] Could not verify log chain: {e}")

        # Verify Environment
        env_lock_path = os.path.join(temp_dir, "environment.lock")
        if os.path.exists(env_lock_path):
            try:
                with open(env_lock_path, "r") as f:
                    env_info = json.load(f)

                if "vouch_version" in env_info:
                    if env_info["vouch_version"] != vouch.__version__:
                        print(f"  [WARN] Created with Vouch {env_info['vouch_version']}, verifying with {vouch.__version__}")

                recorded_version = env_info.get("python_version", "").split()[0]
                current_version = sys.version.split()[0]

                if recorded_version != current_version:
                    print(f"  [WARN] Environment Mismatch: Recorded Python {recorded_version}, Current {current_version}")
                else:
                     print(f"  [OK] Environment: Python version matches ({current_version})")
            except Exception as e:
                print(f"  [WARN] Could not verify environment: {e}")

        # Verify Captured Artifacts if present
        artifacts_json_path = os.path.join(temp_dir, "artifacts.json")
        if os.path.exists(artifacts_json_path):
            print("  [...] Verifying captured artifacts...")

            # Verify Artifact Manifest Signature
            artifacts_sig_path = os.path.join(temp_dir, "artifacts.json.sig")
            if os.path.exists(artifacts_sig_path):
                 try:
                     with open(artifacts_sig_path, "rb") as f:
                         art_sig = f.read()
                     CryptoManager.verify_file(pub_key, artifacts_json_path, art_sig)
                     print("    [OK] Artifact Manifest Signature: Valid")
                 except Exception as e:
                     print(f"    [FAIL] Artifact Manifest Signature: Invalid ({e})")
                     sys.exit(1)
            else:
                 print("    [FAIL] Artifact Manifest Signature: Missing (Manifest not signed)")
                 sys.exit(1)

            try:
                with open(artifacts_json_path, "r") as f:
                    manifest = json.load(f)

                data_dir = os.path.join(temp_dir, "data")
                all_valid = True
                total_artifacts = len(manifest)
                processed = 0

                for name, expected_hash in manifest.items():
                    processed += 1
                    # Progress indicator for large artifact sets (every 10 or 10%)
                    if total_artifacts > 10 and (processed % 10 == 0 or processed == total_artifacts):
                         sys.stdout.write(f"\r    Verifying artifacts... {processed}/{total_artifacts}")
                         sys.stdout.flush()

                    # Sanitize path to prevent traversal
                    if os.path.isabs(name) or ".." in name:
                        print(f"    [FAIL] Malformed artifact path: {name}")
                        all_valid = False
                        continue

                    artifact_path = os.path.join(data_dir, name)
                    # Double check that we are still inside data_dir
                    try:
                        common = os.path.commonpath([os.path.abspath(artifact_path), os.path.abspath(data_dir)])
                        if common != os.path.abspath(data_dir):
                             print(f"    [FAIL] Malformed artifact path (traversal): {name}")
                             all_valid = False
                             continue
                    except ValueError:
                         print(f"    [FAIL] Malformed artifact path (invalid/different drive): {name}")
                         all_valid = False
                         continue

                    if not os.path.exists(artifact_path):
                        print(f"    [FAIL] Missing artifact: {name}")
                        all_valid = False
                        continue

                    actual_hash = Hasher.hash_file(artifact_path)
                    if actual_hash == expected_hash:
                        if total_artifacts <= 10:
                            print(f"    [OK] {name}")
                    else:
                        if total_artifacts > 10: print() # Newline if we were progress barring
                        print(f"    [FAIL] {name} (Hash Mismatch)")
                        all_valid = False

                if total_artifacts > 10: print() # Clear progress line
                if all_valid:
                    print("  [OK] Captured Artifacts Integrity: Valid")
                else:
                    print("  [FAIL] Captured Artifacts Integrity: One or more files corrupted or missing")
                    sys.exit(1)

            except Exception as e:
                print(f"  [FAIL] Artifact Verification Error: {e}")
                sys.exit(1)


        # Verify Data if provided (External verification)
        if data_file:
            if not os.path.exists(data_file):
                print(f"Error: Data file {data_file} not found.")
                sys.exit(1)

            data_hash = Hasher.hash_file(data_file)
            print(f"  [...] Verifying external data file: {data_file}")
            print(f"        Hash: {data_hash}")

            # Load log and search for hash
            with open(os.path.join(temp_dir, "audit_log.json"), "r") as f:
                log = json.load(f)

            found = False
            for entry in log:
                # Check extra_hashes if present
                if "extra_hashes" in entry:
                    for key, val in entry["extra_hashes"].items():
                        if val == data_hash:
                            found = True
                            break
                if found:
                    break

            if found:
                print("  [OK] Data Integrity: Valid")
            else:
                print(f"  [FAIL] Data Integrity: Mismatched/Corrupted (Hash {data_hash} not found in log)")
                sys.exit(1)

        # Auto-verify referenced files
        if args.auto_data:
            print("  [...] Auto-verifying referenced files...")
            auto_data_dir = args.auto_data_dir if args.auto_data_dir else "."

            with open(os.path.join(temp_dir, "audit_log.json"), "r") as f:
                log = json.load(f)

            referenced_files = {} # path -> expected_hash

            for entry in log:
                if "extra_hashes" in entry:
                    extras = entry["extra_hashes"]
                    # Look for keys ending in _path
                    for key, path in extras.items():
                        if key.endswith("_path") and isinstance(path, str):
                            # Find corresponding hash key
                            hash_key = key.replace("_path", "_file_hash")
                            if hash_key in extras:
                                referenced_files[path] = extras[hash_key]

            if not referenced_files:
                print("    No external file references found in log.")
            else:
                all_auto_valid = True
                for path, expected_hash in referenced_files.items():
                    # Resolve path
                    if os.path.isabs(path):
                        target_path = path
                    else:
                        target_path = os.path.join(auto_data_dir, path)

                    if not os.path.exists(target_path):
                         # If absolute path didn't work, try relative to auto_data_dir as fallback?
                         # Or just report missing.
                         # For now, strict check on location.
                         # But also try basename relative to auto_data_dir for convenience
                         fallback_path = os.path.join(auto_data_dir, os.path.basename(path))
                         if os.path.exists(fallback_path):
                             target_path = fallback_path
                         else:
                            print(f"    [SKIP] {path} (Not found)")
                            continue

                    current_hash = Hasher.hash_file(target_path)
                    if current_hash == expected_hash:
                        print(f"    [OK] {target_path}")
                    else:
                        print(f"    [FAIL] {target_path} (Hash mismatch)")
                        all_auto_valid = False

                if not all_auto_valid:
                    print("  [FAIL] Auto-Data Verification: One or more files failed verification")
                    sys.exit(1)
                else:
                    print("  [OK] Auto-Data Verification: Valid")

def gen_keys(args):
    print("Generating RSA keys...")
    private = "id_rsa"
    public = "id_rsa.pub"
    if args.name:
        private = args.name
        public = args.name + ".pub"

    CryptoManager.generate_keys(private, public, password=args.password)
    print(f"Generated {private} and {public}")

def report(args):
    print(f"Generating report for {args.file}...")
    try:
        Reporter.generate_report(args.file, args.output, format=args.format)
        print(f"Report saved to {args.output}")
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)

def diff(args):
    Differ.diff_sessions(args.file1, args.file2, args.show_hashes)

def inspect(args):
    InspectorShell(args.file).cmdloop()

def main():
    parser = argparse.ArgumentParser(description="Vouch: Forensic Audit Wrapper")
    subparsers = parser.add_subparsers(dest="command")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a .vch package")
    verify_parser.add_argument("file", help="Path to .vch file")
    verify_parser.add_argument("--data", help="Verify data integrity against a local file")
    verify_parser.add_argument("--auto-data", action="store_true", help="Automatically verify all files referenced in the log")
    verify_parser.add_argument("--auto-data-dir", help="Directory to search for referenced files (default: current directory)")

    # gen-keys
    gen_keys_parser = subparsers.add_parser("gen-keys", help="Generate RSA key pair")
    gen_keys_parser.add_argument("--name", help="Base name for keys (default: id_rsa)")
    gen_keys_parser.add_argument("--password", help="Password for private key encryption")

    # report
    report_parser = subparsers.add_parser("report", help="Generate an HTML or Markdown report")
    report_parser.add_argument("file", help="Path to .vch file")
    report_parser.add_argument("output", help="Path to output file")
    report_parser.add_argument("--format", choices=["html", "md"], default="html", help="Report format (default: html)")

    # diff
    diff_parser = subparsers.add_parser("diff", help="Compare two .vch files")
    diff_parser.add_argument("file1", help="Path to first .vch file")
    diff_parser.add_argument("file2", help="Path to second .vch file")
    diff_parser.add_argument("--show-hashes", action="store_true", help="Display full hashes for mismatches")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Interactive inspector")
    inspect_parser.add_argument("file", help="Path to .vch file")

    args = parser.parse_args()

    if args.command == "verify":
        verify(args)
    elif args.command == "gen-keys":
        gen_keys(args)
    elif args.command == "report":
        report(args)
    elif args.command == "diff":
        diff(args)
    elif args.command == "inspect":
        inspect(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
