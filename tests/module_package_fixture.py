"""Explicit dependency injection for synthetic RVF protocol tests only."""

import hashlib
import inspect
import json
from pathlib import Path
from types import MappingProxyType

from firmware.qualification_packages import (
    UNCONFIGURED,
    QualificationPackage,
    get_package,
)

DIRECTORY = Path(__file__).resolve().parent / "fixtures/modules"
DOCUMENT = json.loads((DIRECTORY / "catalog.json").read_text())
PACKAGES = MappingProxyType(
    {
        row["profile"]: QualificationPackage(
            path=DIRECTORY / row["file"],
            **{k: v for k, v in row.items() if k != "file"},
        )
        for row in DOCUMENT["packages"]
    }
)
HOME_SIGNAL = PACKAGES["home-signal"]
HOME_SIGNAL_V2 = PACKAGES["home-signal-v2"]
HOME_SIGNAL_V5 = PACKAGES["home-signal-v5"]


def bind_module(module):
    """Inject approved fictional dependencies, preserving real protocol functions."""
    for value in vars(module).values():
        if inspect.isfunction(value) and value.__module__ == module.__name__:
            if value.__defaults__:
                value.__defaults__ = tuple(
                    HOME_SIGNAL if v is UNCONFIGURED else v for v in value.__defaults__
                )
            if value.__kwdefaults__:
                value.__kwdefaults__ = {
                    k: HOME_SIGNAL if v is UNCONFIGURED else v
                    for k, v in value.__kwdefaults__.items()
                }
    module.HOME_SIGNAL = HOME_SIGNAL
    module.PACKAGES = PACKAGES
    module.PACKAGE = HOME_SIGNAL.path
    module.PACKAGE_SHA = HOME_SIGNAL.package_sha256
    module.WASM_SHA = HOME_SIGNAL.wasm_sha256
    module.get_package = lambda profile: get_package(profile, PACKAGES)


def package_arguments(directory):
    path = Path(directory).resolve() / "package-catalog.json"
    raw = (DIRECTORY / "catalog.json").read_bytes()
    path.write_bytes(raw)
    path.chmod(0o600)
    return [
        "--package-catalog",
        str(path),
        "--package-catalog-sha256",
        hashlib.sha256(raw).hexdigest(),
        "--package-directory",
        str(DIRECTORY),
    ]
