import cmd
import os
import json
import zipfile
import tempfile
import shutil
import sys
from datetime import datetime

class InspectorShell(cmd.Cmd):
    intro = 'Welcome to the Vouch Inspector. Type help or ? to list commands.\n'
    prompt = '(vouch) '

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
        self.temp_dir = tempfile.mkdtemp()
        self.loaded = False
        self.audit_log = []
        self.environment = {}
        self.artifacts = {}
        self.manifest = {}

        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                # Safe extraction (Zip Slip protection)
                for member in z.infolist():
                    name = member.filename
                    if name.startswith('/') or '..' in name:
                        print(f"Warning: Skipping suspicious file path in package: {name}")
                        continue

                    target_path = os.path.join(self.temp_dir, name)
                    # Canonicalize
                    if os.path.commonpath([os.path.abspath(target_path), os.path.abspath(self.temp_dir)]) != os.path.abspath(self.temp_dir):
                        print(f"Warning: Skipping artifact with path traversal: {name}")
                        continue

                    z.extract(member, self.temp_dir)

            with open(os.path.join(self.temp_dir, "audit_log.json"), 'r') as f:
                self.audit_log = json.load(f)

            if os.path.exists(os.path.join(self.temp_dir, "environment.lock")):
                with open(os.path.join(self.temp_dir, "environment.lock"), 'r') as f:
                    self.environment = json.load(f)

            if os.path.exists(os.path.join(self.temp_dir, "artifacts.json")):
                with open(os.path.join(self.temp_dir, "artifacts.json"), 'r') as f:
                    self.manifest = json.load(f)

            self.loaded = True
            print(f"Loaded {filepath}")
            self.do_summary(None)
        except Exception as e:
            print(f"Error loading package: {e}")
            self.do_quit(None)

    def do_summary(self, arg):
        """Show summary of the audit package."""
        print("\n=== Audit Package Summary ===")
        print(f"File: {self.filepath}")
        print(f"Vouch Version: {self.environment.get('vouch_version', 'Unknown')}")
        print(f"Python Version: {self.environment.get('python_version', 'Unknown')}")
        print(f"Platform: {self.environment.get('platform', 'Unknown')}")
        print(f"Total Log Entries: {len(self.audit_log)}")
        print(f"Total Artifacts: {len(self.manifest)}")

        # Time range
        if self.audit_log:
            start = self.audit_log[0].get("timestamp", "N/A")
            end = self.audit_log[-1].get("timestamp", "N/A")
            print(f"Time Range: {start} to {end}")
        print("=============================\n")

    def do_timeline(self, arg):
        """List audit log operations chronologically. Usage: timeline [n] (show last n, default all)"""
        if not self.audit_log:
            print("Audit log is empty.")
            return

        limit = len(self.audit_log)
        if arg:
            try:
                limit = int(arg)
            except ValueError:
                print("Invalid number.")
                return

        print("\n=== Timeline ===")
        start_idx = max(0, len(self.audit_log) - limit)
        for i in range(start_idx, len(self.audit_log)):
            entry = self.audit_log[i]
            ts = entry.get("timestamp", "").split("T")[-1][:8] # Simple time
            action = entry.get("action", "unknown")
            target = entry.get("target", "unknown")
            print(f"[{i:4d}] {ts} - {action} {target}")
        print("================\n")

    def do_show(self, arg):
        """Show details of a specific log entry. Usage: show <index>"""
        if not arg:
            print("Usage: show <index>")
            return

        try:
            idx = int(arg)
            if idx < 0 or idx >= len(self.audit_log):
                print(f"Index out of range (0-{len(self.audit_log)-1})")
                return
        except ValueError:
            print("Invalid index.")
            return

        entry = self.audit_log[idx]
        print(f"\n=== Log Entry #{idx} ===")
        print(json.dumps(entry, indent=2))
        print("========================\n")

    def do_artifacts(self, arg):
        """List captured artifacts."""
        if not self.manifest:
            print("No artifacts found.")
            return

        print("\n=== Artifacts ===")
        for name, hash_val in self.manifest.items():
            print(f"Name: {name}")
            print(f"Hash: {hash_val}")
            print("-" * 20)
        print("=================\n")

    def do_quit(self, arg):
        """Exit the inspector."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        print("Bye!")
        return True

    def do_exit(self, arg):
        """Exit the inspector."""
        return self.do_quit(arg)
