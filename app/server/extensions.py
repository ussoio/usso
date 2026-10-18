"""Load trusted deployment overlays without coupling the shared core to them."""

from importlib import import_module

from fastapi import FastAPI


def load_extensions(app: FastAPI, configured: str) -> None:
    """Install each configured module once, failing startup on invalid config."""
    modules = dict.fromkeys(name.strip() for name in configured.split(","))
    for name in modules:
        if name:
            import_module(name).install(app)
