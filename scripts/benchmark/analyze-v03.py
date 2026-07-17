#!/usr/bin/env python3
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).parents[1] / "analyze-v03-bench.py"), run_name="__main__")
