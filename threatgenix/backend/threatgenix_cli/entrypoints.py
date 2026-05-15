"""Console-script bootstraps that avoid importing customer repo modules."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _remove_customer_cwd_from_import_path() -> None:
    cwd = Path(os.getcwd()).resolve()
    sanitized: list[str] = []
    for raw_path in sys.path:
        path = Path(raw_path or os.getcwd()).resolve()
        if path == cwd:
            continue
        sanitized.append(raw_path)
    sys.path[:] = sanitized


def threatgenix_main() -> int:
    _remove_customer_cwd_from_import_path()
    from app.cli.threatgenix import main

    return main()


def threatgenix_mcp_main() -> int:
    _remove_customer_cwd_from_import_path()
    from app.cli.threatgenix_mcp import main

    return main()
