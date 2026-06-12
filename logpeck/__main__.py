# ==============================================================================
# logpeck: __main__.py
# The Package Entry Point for MongoDB Log Forensics.
# ==============================================================================
# This module allows LogPeck to be executed as a module: `python3 -m logpeck`.
# It simply dispatches to the unified CLI router.
# ==============================================================================

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
