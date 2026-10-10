"""Pytest config: the disk cache is disabled by default to isolate tests
(cache-specific tests re-enable it explicitly via monkeypatch)."""

import os

os.environ.setdefault("OSINTLLM_NO_CACHE", "1")
