import argparse
import sys
import os
import zipfile
import tempfile
import shutil
import json
from .crypto import CryptoManager
from .hasher import Hasher

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

        # Verify Captured Artifacts if present
        artifacts_json_path = os.path.join(temp_dir, "artifacts.json")
        if os.path.exists(artifacts_json_path):
            print("  [...] Verifying captured artifacts...")
            try:
                with open(artifacts_json_path, "r") as f:
                    manifest = json.load(f)

                data_dir = os.path.join(temp_dir, "data")
                all_valid = True

                for name, expected_hash in manifest.items():
                    # Sanitize path to prevent traversal
                    if os.path.isabs(name) or ".." in name:
                        print(f"    [FAIL] Malformed artifact path: {name}")
                        all_valid = False
                        continue

                    artifact_path = os.path.join(data_dir, name)
                    # Double check that we are still inside data_dir
                    if not os.path.commonpath([os.path.abspath(artifact_path), os.path.abspath(data_dir)]) == os.path.abspath(data_dir):
                         print(f"    [FAIL] Malformed artifact path (traversal): {name}")
                         all_valid = False
                         continue

                    if not os.path.exists(artifact_path):
                        print(f"    [FAIL] Missing artifact: {name}")
                        all_valid = False
                        continue

                    actual_hash = Hasher.hash_file(artifact_path)
                    if actual_hash == expected_hash:
                        print(f"    [OK] {name}")
                    else:
                        print(f"    [FAIL] {name} (Hash Mismatch)")
                        all_valid = False

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

def gen_keys(args):
    print("Generating RSA keys...")
    private = "id_rsa"
    public = "id_rsa.pub"
    if args.name:
        private = args.name
        public = args.name + ".pub"

    CryptoManager.generate_keys(private, public)
    print(f"Generated {private} and {public}")

def main():
    parser = argparse.ArgumentParser(description="Vouch: Forensic Audit Wrapper")
    subparsers = parser.add_subparsers(dest="command")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a .vch package")
    verify_parser.add_argument("file", help="Path to .vch file")
    verify_parser.add_argument("--data", help="Verify data integrity against a local file")

    # gen-keys
    gen_keys_parser = subparsers.add_parser("gen-keys", help="Generate RSA key pair")
    gen_keys_parser.add_argument("--name", help="Base name for keys (default: id_rsa)")

    args = parser.parse_args()

    if args.command == "verify":
        verify(args)
    elif args.command == "gen-keys":
        gen_keys(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
