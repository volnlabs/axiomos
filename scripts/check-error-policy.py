#!/usr/bin/env python3
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).parent / "verify" / "error-policy.py"), run_name="__main__")
