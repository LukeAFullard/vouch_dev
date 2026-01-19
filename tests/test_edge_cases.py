import unittest
import os
import shutil
import tempfile
import json
import zipfile
from vouch.session import TraceSession
from vouch.hasher import Hasher

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vch_file = os.path.join(self.test_dir, "edge_cases.vch")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_unicode_filenames(self):
        """Test handling of artifacts with unicode characters in filenames"""
        # Create a file with unicode name
        filename = "data_📊_test.csv"
        filepath = os.path.join(self.test_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("column1,column2\n1,2")

        with TraceSession(self.vch_file) as sess:
            sess.add_artifact(filepath)

        # Verify it exists in the zip with correct name
        with zipfile.ZipFile(self.vch_file, 'r') as z:
            # zipfile handles unicode names automatically in modern python
            # stored path should be data/data_📊_test.csv
            expected_name = f"data/{filename}"
            self.assertIn(expected_name, z.namelist())

            # Verify content
            with z.open(expected_name) as f:
                content = f.read().decode("utf-8")
                self.assertEqual(content, "column1,column2\n1,2")

        # Verify manifest
        with zipfile.ZipFile(self.vch_file, 'r') as z:
            manifest = json.loads(z.read("artifacts.json"))
            self.assertIn(filename, manifest)

    def test_zero_byte_file(self):
        """Test handling of zero-byte artifacts"""
        filename = "empty.txt"
        filepath = os.path.join(self.test_dir, filename)
        with open(filepath, "w") as f:
            pass # Create empty file

        with TraceSession(self.vch_file) as sess:
            sess.add_artifact(filepath)

        with zipfile.ZipFile(self.vch_file, 'r') as z:
            expected_name = f"data/{filename}"
            self.assertIn(expected_name, z.namelist())
            info = z.getinfo(expected_name)
            self.assertEqual(info.file_size, 0)

            # Verify hash in manifest (should be hash of empty string)
            manifest = json.loads(z.read("artifacts.json"))
            # sha256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            self.assertEqual(manifest[filename], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_nested_directories(self):
        """Test artifacts in nested directories"""
        # Structure: <test_dir>/subdir/nested/data.txt
        nested_dir = os.path.join(self.test_dir, "subdir", "nested")
        os.makedirs(nested_dir)
        filename = "data.txt"
        filepath = os.path.join(nested_dir, filename)
        with open(filepath, "w") as f:
            f.write("nested data")

        with TraceSession(self.vch_file) as sess:
            # We want to preserve the structure "subdir/nested/data.txt" in the artifact
            # arcname allows this
            sess.add_artifact(filepath, arcname="subdir/nested/data.txt")

        with zipfile.ZipFile(self.vch_file, 'r') as z:
            expected_name = "data/subdir/nested/data.txt"
            self.assertIn(expected_name, z.namelist())

            with z.open(expected_name) as f:
                self.assertEqual(f.read().decode("utf-8"), "nested data")

            manifest = json.loads(z.read("artifacts.json"))
            self.assertIn("subdir/nested/data.txt", manifest)

    def test_large_number_of_artifacts(self):
        """Test bundling a larger number of small files"""
        # Create 100 small files
        files = []
        for i in range(100):
            name = f"file_{i}.txt"
            path = os.path.join(self.test_dir, name)
            with open(path, "w") as f:
                f.write(f"content {i}")
            files.append((name, path))

        with TraceSession(self.vch_file) as sess:
            for name, path in files:
                sess.add_artifact(path)

        with zipfile.ZipFile(self.vch_file, 'r') as z:
            manifest = json.loads(z.read("artifacts.json"))
            self.assertEqual(len(manifest), 100)
            for i in range(100):
                self.assertIn(f"data/file_{i}.txt", z.namelist())

if __name__ == "__main__":
    unittest.main()
