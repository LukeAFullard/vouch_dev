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
from .verifier import Verifier
from .reporter import Reporter
from .differ import Differ
from .inspector import InspectorShell
import logging

def verify(args):
    filepath = args.file

    # Configure logging (still useful for libraries used by Verifier)
    logging.basicConfig(format='  %(message)s', level=logging.INFO, force=True, stream=sys.stdout)

    print(f"Verifying {filepath}...")

    def cli_reporter(msg, level="INFO", check_name=None):
        print(msg)

    verifier = Verifier(filepath)
    success = verifier.verify(
        data_file=args.data,
        auto_data=args.auto_data,
        auto_data_dir=args.auto_data_dir if args.auto_data_dir else ".",
        tsa_ca_file=args.tsa_ca_file if hasattr(args, 'tsa_ca_file') else None,
        strict=getattr(args, 'strict', False),
        trusted_public_key_path=getattr(args, 'public_key', None),
        reporter=cli_reporter
    )

    if success:
        print("Verification Successful.")
    else:
        print("Verification Failed.")
        sys.exit(1)

def gen_keys(args):
    print("Generating RSA keys...")
    private = "id_rsa"
    public = "id_rsa.pub"
    if args.name:
        private = args.name
        public = args.name + ".pub"

    cert_path = None
    if args.cert:
        cert_path = public.replace(".pub", ".crt") if public.endswith(".pub") else public + ".crt"

    CryptoManager.generate_keys(
        private,
        public,
        password=args.password,
        cert_path=cert_path,
        days=args.days,
        common_name=args.common_name,
        organization=args.org
    )
    print(f"Generated {private} and {public}")
    if cert_path:
        print(f"Generated Certificate {cert_path}")

def init(args):
    """Initialize Vouch configuration and keys."""
    # Determine location: local .vouch or global ~/.vouch
    if args.global_config:
        config_dir = os.path.expanduser("~/.vouch")
    else:
        config_dir = os.path.join(os.getcwd(), ".vouch")

    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
        print(f"Created configuration directory: {config_dir}")
    else:
        print(f"Configuration directory exists: {config_dir}")

    # Check for keys
    priv_key_path = os.path.join(config_dir, "id_rsa")
    pub_key_path = os.path.join(config_dir, "id_rsa.pub")

    if os.path.exists(priv_key_path):
        print(f"Keys already exist in {config_dir}")
    else:
        print(f"Generating new keys in {config_dir}...")
        try:
            CryptoManager.generate_keys(priv_key_path, pub_key_path, password=args.password)
            print("Keys generated successfully.")
            print("You are now ready to use Vouch!")
        except Exception as e:
            print(f"Error generating keys: {e}")
            sys.exit(1)

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

    # init
    init_parser = subparsers.add_parser("init", help="Initialize Vouch (generate keys and config)")
    init_parser.add_argument("--global", dest="global_config", action="store_true", help="Initialize in user home directory (~/.vouch)")
    init_parser.add_argument("--password", help="Password for private key encryption")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a .vch package")
    verify_parser.add_argument("file", help="Path to .vch file")
    verify_parser.add_argument("--data", help="Verify data integrity against a local file")
    verify_parser.add_argument("--auto-data", action="store_true", help="Automatically verify all files referenced in the log")
    verify_parser.add_argument("--auto-data-dir", help="Directory to search for referenced files (default: current directory)")
    verify_parser.add_argument("--tsa-ca-file", help="Path to TSA CA certificate for timestamp verification")
    verify_parser.add_argument("--strict", action="store_true", help="Fail verification if timestamp validation fails")
    verify_parser.add_argument("--public-key", help="Path to a trusted public key for signature verification")

    # gen-keys
    gen_keys_parser = subparsers.add_parser("gen-keys", help="Generate RSA key pair")
    gen_keys_parser.add_argument("--name", help="Base name for keys (default: id_rsa)")
    gen_keys_parser.add_argument("--password", help="Password for private key encryption")
    gen_keys_parser.add_argument("--cert", action="store_true", help="Generate an X.509 certificate instead of raw public key")
    gen_keys_parser.add_argument("--days", type=int, default=365, help="Validity period for certificate in days (default: 365)")
    gen_keys_parser.add_argument("--common-name", help="Common Name (CN) for the certificate (e.g. your name)", default="vouch-generated-cert")
    gen_keys_parser.add_argument("--org", help="Organization (O) for the certificate", default="Vouch User")

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
    elif args.command == "init":
        init(args)
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
