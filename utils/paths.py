"""Filesystem locations for config, data, and logs.

Historically every path was a relative string such as ``config/config.yaml``
or ``data/deep_eye.db``, resolved against the process working directory. That
breaks the moment the tool runs from a different directory, a scheduler, or a
container with a read-only app directory.

Resolution order for each root, highest priority first:

1. An explicit environment variable (``DEEP_EYE_CONFIG_DIR`` etc.)
2. ``--config`` / an absolute path supplied by the caller (handled by callers)
3. The per-user application directory for the platform
4. The repository directory, only when it already contains the expected files

Nothing here creates directories or touches the filesystem on import; callers
call :func:`ensure_dirs` when they actually need the tree to exist.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

APP_NAME = "deep-eye"
APP_DIR_NAME = ".deep-eye"

CONFIG_ENV = "DEEP_EYE_CONFIG_DIR"
DATA_ENV = "DEEP_EYE_DATA_DIR"
LOGS_ENV = "DEEP_EYE_LOGS_DIR"
HOME_ENV = "DEEP_EYE_HOME"

CONFIG_FILENAME = "config.yaml"


def repo_root() -> Path:
    """Directory containing the running package (the checkout)."""
    return Path(__file__).resolve().parent.parent


def user_home_root() -> Path:
    """Per-user application directory for this platform.

    Windows uses ``%APPDATA%``, macOS uses ``~/Library/Application Support``,
    everything else follows the XDG base directory spec. ``DEEP_EYE_HOME``
    overrides all three, which is what tests and sandboxes use.
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / APP_DIR_NAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def _resolve(env_var: str, default: Path) -> Path:
    override = os.environ.get(env_var)
    if override:
        return Path(override).expanduser()
    return default


def config_dir() -> Path:
    return _resolve(CONFIG_ENV, user_home_root() / "config")


def data_dir() -> Path:
    return _resolve(DATA_ENV, user_home_root() / "data")


def logs_dir() -> Path:
    return _resolve(LOGS_ENV, user_home_root() / "logs")


def config_path() -> Path:
    """Default config file location."""
    return config_dir() / CONFIG_FILENAME


def repo_config_path() -> Path:
    """The in-repo config location, used for migration and local development."""
    return repo_root() / "config" / CONFIG_FILENAME


def example_config_path() -> Path:
    return repo_root() / "config" / "config.example.yaml"


def db_path(name: str = "deep_eye.db") -> Path:
    return data_dir() / name


def cve_db_path() -> Path:
    return data_dir() / "cve_intelligence.db"


def rag_index_path() -> Path:
    return data_dir() / "cve_rag_index.pkl"


def checkpoints_dir() -> Path:
    return data_dir() / "checkpoints"


def auth_sessions_path() -> Path:
    return data_dir() / "auth_sessions.json"


def reports_dir() -> Path:
    """Reports stay relative to the working directory by design.

    Scan output is something people open from the project they scanned, not
    from an application data directory. ``reporting.output_directory`` still
    overrides this.
    """
    return Path("reports")


def ensure_dirs() -> None:
    """Create the config, data, and logs directories if missing."""
    for directory in (config_dir(), data_dir(), logs_dir()):
        directory.mkdir(parents=True, exist_ok=True)


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def migrate_repo_config(force: bool = False) -> Optional[Path]:
    """Copy an existing in-repo config into the user config directory.

    Returns the destination path when a migration happened, otherwise None.
    An existing destination is never overwritten unless ``force`` is set, so a
    user who already configured the tool cannot lose their settings to a stale
    checkout file.
    """
    source = repo_config_path()
    destination = config_path()

    if not source.exists():
        return None
    if source.resolve() == destination.resolve():
        return None
    if destination.exists() and not force:
        return None

    _atomic_copy(source, destination)
    return destination


def resolve_config(explicit: Optional[str] = None, migrate: bool = True) -> Path:
    """Pick the config file to use, migrating a repo config when that is the only one.

    An explicit path always wins and is returned untouched (callers surface a
    missing-file error themselves). Without one, a migrated user config is
    preferred over the checkout copy.
    """
    if explicit:
        return Path(explicit).expanduser()

    destination = config_path()
    if destination.exists():
        return destination

    if migrate:
        migrated = migrate_repo_config()
        if migrated:
            return migrated

    if repo_config_path().exists():
        return repo_config_path()

    return destination


def describe() -> dict:
    """Current resolved locations, for ``--check-config`` and diagnostics."""
    return {
        "home": str(user_home_root()),
        "config_dir": str(config_dir()),
        "config_file": str(config_path()),
        "data_dir": str(data_dir()),
        "logs_dir": str(logs_dir()),
        "repo_root": str(repo_root()),
        "repo_config": str(repo_config_path()),
        "reports_dir": str(reports_dir()),
    }
