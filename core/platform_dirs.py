"""Small shared platform-directory helpers for tunnel session configs.

The usque manager imports this module so that session files follow the
application's configured root instead of hard-coding a second path. The
environment override is useful for tests and for read-only installations.
"""

import os


def config_dir() -> str:
    """Return the zapret-gui persistent configuration root."""
    override = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
    if override:
        return override
    try:
        # Respect create_app(config_dir=...) and test/application overrides.
        from core.config_manager import get_config_manager
        configured = getattr(get_config_manager(), "_config_dir", "")
        if configured:
            return configured
    except Exception:
        pass
    return "/opt/etc/zapret-gui"
