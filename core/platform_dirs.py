"""Small shared platform-directory helpers for tunnel session configs.

The usque manager imports this module so that session files follow the
application's configured root instead of hard-coding a second path. The
environment override is useful for tests and for read-only installations.
"""

import os


def config_dir() -> str:
    """Return the zapret-gui persistent configuration root."""
    return os.environ.get("ZAPRET_GUI_CONFIG_DIR", "/opt/etc/zapret-gui")

