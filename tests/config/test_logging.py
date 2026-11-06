"""`app.config.logging` import-time behaviour.

Two import-time side effects are under test:

1. `_auto_configure()` — must NOT propagate a Settings validation error.
   With an empty env and no `.env` in cwd, `Settings()` fails on the
   required `kafka_bootstrap_servers`; the module must fall back to safe
   defaults (INFO / console) instead of making `import app.config.logging`
   blow up with a Pydantic traceback.
2. The `builtins.print` monkey-patch — must be reload-idempotent (sentinel
   guard), otherwise every `importlib.reload` wraps the previous wrapper.

The empty-env case runs in a subprocess: in-process the settings singleton
is already built and the repo's `.env`/test env would mask the failure.
"""

from __future__ import annotations

import builtins
import importlib
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_import_succeeds_with_empty_env(tmp_path):
    """`import app.config.logging` must survive an unloadable Settings()."""
    result = subprocess.run(
        [sys.executable, "-c", "import app.config.logging; print('IMPORT_OK')"],
        cwd=tmp_path,  # no .env here — Settings() has no kafka_bootstrap_servers
        env={
            "PYTHONPATH": str(REPO_ROOT),
            "PATH": os.environ.get("PATH", ""),
            # Keep HOME so user-level python config doesn't break interpreter boot.
            "HOME": os.environ.get("HOME", str(tmp_path)),
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    assert "IMPORT_OK" in result.stdout
    # The fallback announces itself once on stderr (not a silent swallow).
    assert "settings unavailable" in result.stderr


def test_import_with_valid_env_does_not_warn(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", "import app.config.logging; print('IMPORT_OK')"],
        cwd=tmp_path,
        env={
            "PYTHONPATH": str(REPO_ROOT),
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", str(tmp_path)),
            "KAFKA_BOOTSTRAP_SERVERS": "dummy:9092",
            "KAFKA_AUTH_METHOD": "PLAINTEXT",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    assert "IMPORT_OK" in result.stdout
    assert "settings unavailable" not in result.stderr


def test_print_patch_is_reload_idempotent():
    """Reloading the module must not re-wrap builtins.print."""
    import app.config.logging as logging_mod

    patched_before = builtins.print
    assert getattr(patched_before, "_detectflow_flink_safe", False)

    importlib.reload(logging_mod)
    importlib.reload(logging_mod)

    # Same wrapper object — no wrapper-around-wrapper chain grew.
    assert builtins.print is patched_before
    # And the wrapper still swallows `flush` (the reason the patch exists).
    print("reload-idempotency probe", flush=True)
