import subprocess
import shutil
import logging
import json

logger = logging.getLogger(__name__)

class GitTracker:
    @staticmethod
    def is_git_repo():
        return shutil.which("git") and subprocess.call(
            ["git", "rev-parse", "--is-inside-work-tree"],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        ) == 0

    @staticmethod
    def get_metadata():
        if not GitTracker.is_git_repo():
            return None

        try:
            # Commit SHA
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

            # Branch
            branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).decode().strip()

            # Dirty check
            status = subprocess.check_output(["git", "status", "--porcelain"]).decode().strip()
            is_dirty = bool(status)

            # Diff (if dirty)
            diff = ""
            if is_dirty:
                diff = subprocess.check_output(["git", "diff"]).decode()

            return {
                "commit_sha": sha,
                "branch": branch,
                "is_dirty": is_dirty,
                "diff": diff
            }
        except Exception as e:
            logger.warning(f"Failed to capture git metadata: {e}")
            return None
