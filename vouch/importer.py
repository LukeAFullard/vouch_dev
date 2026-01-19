import sys
import importlib
import inspect
from importlib.abc import MetaPathFinder, Loader
from contextlib import contextmanager
from .auditor import Auditor

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
    def __init__(self, targets=None):
        if targets is None:
            self.targets = {"pandas", "numpy"}
        else:
            self.targets = set(targets)

        # Determine strict exclusion list
        self.excludes = {"vouch", "pytest", "unittest", "pip", "setuptools", "wheel", "_pytest", "pluggy", "iniconfig", "packaging"}
        if hasattr(sys, "stdlib_module_names"):
             self.excludes.update(sys.stdlib_module_names)

    def _should_audit(self, fullname):
        if fullname in self.excludes:
            return False
        if any(fullname.startswith(p + ".") for p in self.excludes):
            return False

        if "*" in self.targets:
             return True

        return fullname in self.targets

    def find_spec(self, fullname, path, target=None):
        if self._should_audit(fullname):
            # Remove self to find original spec
            sys.meta_path = [x for x in sys.meta_path if x is not self]
            try:
                spec = importlib.util.find_spec(fullname)
            except Exception:
                # If find_spec fails, we can't wrap it
                spec = None
            finally:
                sys.meta_path.insert(0, self)

            if spec and spec.loader:
                # Only wrap if it's not a builtin/extension that might break?
                # For now, wrap everything that has a loader.
                spec.loader = VouchLoader(spec.loader, fullname)
                return spec
        return None

def _patch_caller_globals(targets, finder):
    try:
        # stack[0] = this function
        # stack[1] = auto_audit (the generator context manager)
        # stack[2] = TraceSession.__enter__ (if used via context manager) OR start (if used via wrapper?)

        # When using @vouch.record:
        # wrapper -> with start() -> TraceSession.__enter__ -> auto_audit.__enter__ -> _patch_caller_globals

        # We want to find the frame where the user's code lives.
        # This is typically the frame that CALLED the `vouch` entry point.

        stack = inspect.stack()
        for i, frame_info in enumerate(stack):
            # Skip first few frames (internal)
            if i < 2: continue

            frame = frame_info.frame
            module_name = frame.f_globals.get("__name__")

            # print(f"DEBUG Frame {i}: {module_name} ({frame_info.function}) in {frame_info.filename}")

            # Skip vouch modules and contextlib (which handles context managers)
            if module_name and (module_name.startswith("vouch") or module_name == "contextlib"):
                continue

            # We found a user frame.
            # Scan its globals for things we should be auditing.
            updates = {}
            for name, val in frame.f_globals.items():
                if isinstance(val, type(sys)): # It's a module
                    mod_name = val.__name__

                    if finder._should_audit(mod_name):
                        # Ensure the authoritative module in sys.modules is wrapped
                        if mod_name in sys.modules:
                            current_mod = sys.modules[mod_name]

                            # If it's not wrapped yet (because it was imported before auditing started),
                            # we should wrap it now in sys.modules first!
                            # (Wait, auto_audit loop does this below? No, auto_audit loop is for explicit targets or *)
                            # The loop in auto_audit handles "explicit targets" and "*".
                            # Here we are patching globals. We rely on the fact that if we found it,
                            # we should have wrapped it.

                            # If sys.modules version is NOT wrapped, we should wrap it now?
                            # This handles the case where target="pandas" but user imported it top-level.
                            if not isinstance(current_mod, Auditor):
                                # Wrap it in sys.modules
                                wrapped = Auditor(current_mod, name=mod_name)
                                sys.modules[mod_name] = wrapped
                                current_mod = wrapped

                            # Now update the global variable to point to the wrapped module
                            if not isinstance(val, Auditor):
                                # print(f"DEBUG: Patching {name} -> wrapped {mod_name}")
                                updates[name] = current_mod

            if updates:
                frame.f_globals.update(updates)
                # print(f"DEBUG: Applied {len(updates)} patches to globals of {module_name}")

            # We assume the first non-vouch/contextlib frame is the one we want to patch.
            # For scripts, this is __main__.
            # For decorated functions, this is the module defining the function.
            break

    except Exception as e:
        # print(f"DEBUG: Patch error: {e}")
        pass

@contextmanager
def auto_audit(targets=None):
    """
    Context manager to automatically wrap specified modules with Auditor.
    targets: list of module names to wrap (default: ['pandas', 'numpy']).
             If targets=['*'], it attempts to wrap all non-standard-library imports.
    """
    if targets is None:
        targets = ["pandas", "numpy"]

    finder = VouchFinder(targets)
    sys.meta_path.insert(0, finder)

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

    # Patch globals in the calling frame to update existing references
    _patch_caller_globals(targets, finder)

    try:
        yield
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)

        # Restore originally loaded modules
        for name, mod in original_modules.items():
            sys.modules[name] = mod
