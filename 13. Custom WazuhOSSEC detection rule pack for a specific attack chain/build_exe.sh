#!/usr/bin/env bash
# Build the portable rule pack builder (for CI / Linux builders).
# Windows exe must be built on Windows; this produces the platform binary.
set -euo pipefail
cd "$(dirname "$0")"
python -m PyInstaller --noconfirm --clean WazuhRulePackBuilder.spec
echo "Built: dist/WazuhRulePackBuilder"