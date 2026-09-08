#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
from datetime import datetime
import uuid
print('k-slide-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:4])
PY
