"""Domain layer: pure, side-effect-free subnet math and VLSM planning.

This package must never import from ui/, app/ or persistence/ so that it
remains fully unit-testable in a headless environment.
"""