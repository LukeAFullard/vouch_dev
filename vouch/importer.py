import sys
import importlib
import inspect
import threading
from importlib.abc import MetaPathFinder, Loader
from contextlib import contextmanager
from .auditor import Auditor

_patch_lock = threading.Lock()

class VouchLoader(Loader):
    def __init__(self, original_loader, name):
        self.original_loader = original_loader
        self.name = name

    def create_module(self, spec):
        if hasattr(self.original_loader, 'create_module'):
             return self.original_loader.create_module(spec)
        return None

    def exec_module(self, module):
        if hasattr(self.original_loader, 'exec_module'):
            self.original_loader.exec_module(module)

        # Wrap and replace in sys.modules
        wrapped = Auditor(module, name=self.name)
        sys.modules[self.name] = wrapped

class VouchFinder(MetaPathFinder):
    def __init__(self, targets=None, excludes=None):
        if targets is None:
            self.targets = {"pandas", "numpy"}
        else:
            self.targets = set(targets)

        # Determine strict exclusion list
        self.base_excludes = {"vouch", "pytest", "unittest", "pip", "setuptools", "wheel", "_pytest", "pluggy", "iniconfig", "packaging"}
        if hasattr(sys, "stdlib_module_names"):
             self.base_excludes.update(sys.stdlib_module_names)

        self.user_excludes = set(excludes) if excludes else set()
        self._thread_local = threading.local()

    def _should_audit(self, fullname):
        # Explicit targets override strict exclusions
        if fullname in self.targets:
            return True

        # User excludes take precedence over wildcard
        if fullname in self.user_excludes:
            return False
        if any(fullname.startswith(p + ".") for p in self.user_excludes):
            return False

        if fullname in self.base_excludes:
            return False
        if any(fullname.startswith(p + ".") for p in self.base_excludes):
            return False

        if "*" in self.targets:
             return True

        return fullname in self.targets

    def find_spec(self, fullname, path, target=None):
        # Re-entrancy guard using thread-local storage to avoid recursion
        # and unsafe modification of sys.meta_path
        if getattr(self._thread_local, 'disabled', False):
            return None

        if self._should_audit(fullname):
            try:
                self._thread_local.disabled = True
                spec = importlib.util.find_spec(fullname)
            except Exception:
                # If find_spec fails, we can't wrap it
                spec = None
            finally:
                self._thread_local.disabled = False

            if spec and spec.loader:
                # Only wrap if it's not a builtin/extension that might break?
                # For now, wrap everything that has a loader.
                spec.loader = VouchLoader(spec.loader, fullname)
                return spec
        return None

def _patch_loaded_modules(finder):
    """
    Iterate over all loaded modules and patch their globals if they reference tracked libraries.
    This solves the limitation where only the caller's globals were patched.
    """
    import os

    for mod_name, module in list(sys.modules.items()):
        # Skip internal/system modules
        if mod_name.startswith("vouch") or mod_name == "contextlib": continue

        # Heuristic: Skip modules that don't look like user code
        if not hasattr(module, '__file__') or not module.__file__:
            continue

        # Skip site-packages / dist-packages (installed libraries)
        if "site-packages" in module.__file__ or "dist-packages" in module.__file__:
            continue

        # Skip standard library (heuristic based on location)
        # sys.base_prefix is where stdlib lives
        lib_path = os.path.join(sys.base_prefix, "lib")
        if module.__file__.startswith(lib_path):
             continue

        try:
            updates = {}
            for name, val in module.__dict__.items():
                if isinstance(val, type(sys)): # It's a module
                    target_name = val.__name__

                    if finder._should_audit(target_name):
                        # Ensure the authoritative module in sys.modules is wrapped
                        if target_name in sys.modules:
                            current_mod = sys.modules[target_name]

                            # If sys.modules version is NOT wrapped, we should wrap it now
                            if not isinstance(current_mod, Auditor):
                                wrapped = Auditor(current_mod, name=target_name)
                                sys.modules[target_name] = wrapped
                                current_mod = wrapped

                            # Now update the module's reference to point to the wrapped module
                            if not isinstance(val, Auditor):
                                updates[name] = current_mod

            if updates:
                module.__dict__.update(updates)
        except Exception:
            pass

@contextmanager
def auto_audit(targets=None, excludes=None):
    """
    Context manager to automatically wrap specified modules with Auditor.
    targets: list of module names to wrap (default: ['pandas', 'numpy']).
             If targets=['*'], it attempts to wrap all non-standard-library imports.
    excludes: list of module names to explicitly exclude from auditing (even if wildcard is used).
    """
    with _patch_lock:
        if targets is None:
            targets = ["pandas", "numpy"]

        finder = VouchFinder(targets, excludes=excludes)
        sys.meta_path.insert(0, finder)

        from .session import TraceSession
        session = TraceSession.get_active_session()
        if session:
            session.register_finder(finder)

        # Handle already loaded modules
        original_modules = {}

        if "*" in targets:
            # Scan sys.modules and wrap anything that passes the filter
            for name in list(sys.modules.keys()):
                if finder._should_audit(name):
                    mod = sys.modules[name]
                    if not isinstance(mod, Auditor):
                        original_modules[name] = mod
                        sys.modules[name] = Auditor(mod, name=name)

        # Wrap specifically listed targets if they are already loaded
        for name in targets:
            if name == "*": continue
            if name in sys.modules:
                mod = sys.modules[name]
                # Avoid double wrapping
                if not isinstance(mod, Auditor):
                    original_modules[name] = mod
                    sys.modules[name] = Auditor(mod, name=name)

        # Patch globals in all user modules to update existing references
        _patch_loaded_modules(finder)

    try:
        yield
    finally:
        with _patch_lock:
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)

            # Restore originally loaded modules
            for name, mod in original_modules.items():
                sys.modules[name] = mod
