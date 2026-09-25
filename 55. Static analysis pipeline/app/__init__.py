"""Static Analysis Pipeline (SAP) - static triage workbench for suspicious PE files."""
from app.config import APP

__all__ = ["APP", "__version__"]
__version__ = APP["version"]
