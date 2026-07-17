#!/usr/bin/env python3
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).parent / "verify" / "abi-surface.py"), run_name="__main__")
