"""Home-directory resolution and first-run config migration."""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _reload_paths(home: Path):
    os.environ["DEEP_EYE_HOME"] = str(home)
    for key in ("DEEP_EYE_CONFIG_DIR", "DEEP_EYE_DATA_DIR", "DEEP_EYE_LOGS_DIR"):
        os.environ.pop(key, None)
    import importlib

    from utils import paths

    return importlib.reload(paths)


def test_home_override_drives_all_roots(tmp_path):
    paths = _reload_paths(tmp_path)
    assert paths.user_home_root() == tmp_path
    assert paths.config_dir() == tmp_path / "config"
    assert paths.data_dir() == tmp_path / "data"
    assert paths.logs_dir() == tmp_path / "logs"


def test_explicit_dir_env_wins_over_home(tmp_path):
    paths = _reload_paths(tmp_path)
    custom = tmp_path / "custom-data"
    os.environ["DEEP_EYE_DATA_DIR"] = str(custom)
    import importlib

    try:
        paths = importlib.reload(paths)
        assert paths.data_dir() == custom
        assert paths.config_dir() == tmp_path / "config"
    finally:
        os.environ.pop("DEEP_EYE_DATA_DIR", None)
        importlib.reload(paths)


def test_reports_stay_relative():
    paths = _reload_paths(Path(os.environ.get("TEMP", "/tmp")) / "de-reports-test")
    assert not paths.reports_dir().is_absolute()


def test_migration_copies_repo_config_once(tmp_path, monkeypatch):
    paths = _reload_paths(tmp_path)
    repo_cfg = tmp_path / "repo" / "config" / "config.yaml"
    repo_cfg.parent.mkdir(parents=True)
    repo_cfg.write_text("scanner:\n  default_threads: 3\n", encoding="utf-8")

    monkeypatch.setattr(paths, "repo_config_path", lambda: repo_cfg)
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path / "repo")

    migrated = paths.migrate_repo_config()
    assert migrated == paths.config_path()
    assert migrated.exists()
    assert "default_threads: 3" in migrated.read_text(encoding="utf-8")


def test_migration_does_not_overwrite_existing(tmp_path, monkeypatch):
    paths = _reload_paths(tmp_path)
    repo_cfg = tmp_path / "repo" / "config" / "config.yaml"
    repo_cfg.parent.mkdir(parents=True)
    repo_cfg.write_text("scanner:\n  default_threads: 3\n", encoding="utf-8")

    existing = paths.config_path()
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_text("scanner:\n  default_threads: 9\n", encoding="utf-8")

    monkeypatch.setattr(paths, "repo_config_path", lambda: repo_cfg)
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path / "repo")

    assert paths.migrate_repo_config() is None
    assert "default_threads: 9" in existing.read_text(encoding="utf-8")


def test_resolve_config_prefers_explicit_path(tmp_path):
    paths = _reload_paths(tmp_path)
    explicit = tmp_path / "somewhere" / "custom.yaml"
    assert paths.resolve_config(str(explicit)) == explicit


def test_resolve_config_returns_home_config_when_present(tmp_path, monkeypatch):
    paths = _reload_paths(tmp_path)
    home_cfg = paths.config_path()
    home_cfg.parent.mkdir(parents=True, exist_ok=True)
    home_cfg.write_text("scanner: {}\n", encoding="utf-8")

    monkeypatch.setattr(paths, "repo_config_path", lambda: tmp_path / "missing.yaml")
    assert paths.resolve_config() == home_cfg


def test_data_paths_live_under_home_data(tmp_path):
    paths = _reload_paths(tmp_path)
    base = tmp_path / "data"
    assert paths.db_path() == base / "deep_eye.db"
    assert paths.cve_db_path() == base / "cve_intelligence.db"
    assert paths.rag_index_path() == base / "cve_rag_index.pkl"
    assert paths.checkpoints_dir() == base / "checkpoints"
    assert paths.auth_sessions_path() == base / "auth_sessions.json"


def test_ensure_dirs_creates_tree(tmp_path):
    paths = _reload_paths(tmp_path)
    assert not paths.config_dir().exists()
    paths.ensure_dirs()
    assert paths.config_dir().exists()
    assert paths.data_dir().exists()
    assert paths.logs_dir().exists()
