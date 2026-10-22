"""Keep the default test suite independent of the developer's real settings file.

`config.settings` is a module-level singleton loaded from the running user's config
(`config/settings.yaml` or the per-user path). Tests assert defaults, so an ambient
engine/provider/output-dir choice must not change their outcome. Opt-in live tests are
exempt: they exist to exercise real credentials.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_LIVE_TESTS_ENABLED = os.getenv("CYBERMAP_RUN_LIVE_TESTS", "").lower() == "true"
if not _LIVE_TESTS_ENABLED and "CYBERMAP_CONFIG" not in os.environ:
    # conftest is imported before any test module, so config.settings picks this up.
    # The page cache is disabled here: a cached page would answer a request without
    # touching the mocked transport and silently invalidate the call assertions.
    _config_path = Path(tempfile.mkdtemp(prefix="cybermap-tests-")) / "settings.yaml"
    _config_path.write_text("cache:\n  enabled: false\n", encoding="utf-8")
    os.environ["CYBERMAP_CONFIG"] = str(_config_path)
