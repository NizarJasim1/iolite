"""Run:
  python3 -m iolite.intent <target.json> [--report out.md]   # Wall-1 interventional engine
  python3 -m iolite.intent pipeline                          # the four-wall kill-chain demo (in-process)
  python3 -m iolite.intent killchain                         # the WIRED kill-chain on a real SurfaceModel (v1.15)
"""
import sys

if len(sys.argv) > 1 and sys.argv[1] == "pipeline":
    from . import pipeline
    raise SystemExit(pipeline.main())
if len(sys.argv) > 1 and sys.argv[1] == "killchain":
    from . import kill_chain
    raise SystemExit(kill_chain.main())
from .engine import main
raise SystemExit(main(sys.argv[1:]))
