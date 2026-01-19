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
    def __init__(self):
        self.targets = {"pandas", "numpy"}

    def find_spec(self, fullname, path, target=None):
        if fullname in self.targets:
            # Remove self to find original spec
            sys.meta_path = [x for x in sys.meta_path if x is not self]
            try:
                spec = importlib.util.find_spec(fullname)
            finally:
                sys.meta_path.insert(0, self)

            if spec and spec.loader:
                spec.loader = VouchLoader(spec.loader, fullname)
                return spec
        return None

@contextmanager
def auto_audit():
    """
    Context manager to automatically wrap pandas and numpy imports with Auditor.
    """
    finder = VouchFinder()
    sys.meta_path.insert(0, finder)

    # Handle already loaded modules
    original_modules = {}
    targets = ["pandas", "numpy"]

    for name in targets:
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
