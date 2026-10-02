import importlib
import ns.inner.mod


def lazy():
    return importlib.import_module("ns.inner.mod")
