
import vouch
import unittest
import os
import json

# Dummy function to audit
def login(username, password, api_key=None):
    return f"User {username} logged in"

# Dummy class to audit
class Database:
    def connect(self, connection_string, password=None):
        return True

class TestRedaction(unittest.TestCase):
    def test_function_redaction(self):
        log_file = "test_redaction.vch"

        # Manually wrap the function since it's in this module
        audited_login = vouch.auditor.Auditor(login, name="login")

        with vouch.start(log_file, strict=False, redact_args=["password", "api_key"]) as session:
            # 1. Positional args
            audited_login("admin", "secret123")

            # 2. Keyword args
            audited_login(username="user2", password="secret456", api_key="xyz-999")

            # 3. Mixed
            audited_login("user3", password="secret789")

            # Flush to ensure log is written
            session.logger._file_handle.flush()

            # Verify log INSIDE session (before temp dir deletion)
            log_path = os.path.join(session.temp_dir, "audit_log.json")
            with open(log_path, "r") as f:
                # Skip session init
                next(f)

                # Entry 1: login("admin", "secret123") -> password is 2nd arg
                entry1 = json.loads(next(f))
                self.assertEqual(entry1["target"], "login")

                print(f"Entry 1 Args: {entry1['args_repr']}")
                self.assertNotIn("secret123", str(entry1))
                self.assertIn("'<REDACTED>'", entry1['args_repr'])

                # Entry 2: login(..., password="...", api_key="...")
                entry2 = json.loads(next(f))
                # Note: inspect.bind normalizes everything to positional args if the function signature allows it.
                # So even though we called with kwargs, they might appear in args_repr.
                print(f"Entry 2 Args: {entry2['args_repr']}")
                print(f"Entry 2 Kwargs: {entry2['kwargs_repr']}")

                self.assertNotIn("secret456", str(entry2))
                self.assertNotIn("xyz-999", str(entry2))
                # Check for redaction in either args or kwargs
                redacted_count = str(entry2).count("REDACTED")
                self.assertGreaterEqual(redacted_count, 2, "Should have at least 2 redacted fields")

    def test_method_redaction(self):
        log_file = "test_redaction_method.vch"

        db = Database()
        audited_db = vouch.auditor.Auditor(db, name="Database")

        with vouch.start(log_file, strict=False, redact_args=["connection_string", "password"]) as session:
            audited_db.connect("postgres://user:pass@localhost", password="db_secret")

            session.logger._file_handle.flush()
            log_path = os.path.join(session.temp_dir, "audit_log.json")
            with open(log_path, "r") as f:
                next(f) # Init
                entry = json.loads(next(f))

                self.assertEqual(entry["target"], "Database.connect")
                self.assertNotIn("postgres://", str(entry))
                self.assertNotIn("db_secret", str(entry))
                self.assertIn("REDACTED", str(entry))

if __name__ == "__main__":
    unittest.main()
