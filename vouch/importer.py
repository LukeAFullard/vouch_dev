import sys
import importlib
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

    try:
        yield
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)

        # Restore originally loaded modules
        for name, mod in original_modules.items():
            sys.modules[name] = mod
