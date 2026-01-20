import unittest
import os
import shutil
import json
import zipfile
from vouch import TraceSession, Auditor

class DataHandler:
    def __init__(self):
        pass
    def ingest_stuff(self, filepath):
        pass
    def export_stuff(self, filepath):
        pass

class TestCustomTriggers(unittest.TestCase):
    def test_custom_triggers(self):
        filename = "test_custom.vch"
        data_file = "trigger_data.txt"
        with open(data_file, "w") as f:
            f.write("data")

        handler = Auditor(DataHandler(), name="handler")

        # Test input trigger
        with TraceSession(filename, strict=False, custom_input_triggers=["ingest_"], custom_output_triggers=["export_"]) as sess:
            handler.ingest_stuff(data_file)
            handler.export_stuff(data_file)

        # Verify
        with zipfile.ZipFile(filename, "r") as z:
            with z.open("audit_log.json") as f:
                log = json.load(f)

        ingest_entry = next(e for e in log if "ingest_stuff" in e["target"])
        export_entry = next(e for e in log if "export_stuff" in e["target"])

        self.assertIn("extra_hashes", ingest_entry)
        self.assertIn("arg_0_file_hash", ingest_entry["extra_hashes"])

        self.assertIn("extra_hashes", export_entry)
        self.assertIn("arg_0_file_hash", export_entry["extra_hashes"])

        os.remove(filename)
        os.remove(data_file)

if __name__ == "__main__":
    unittest.main()
