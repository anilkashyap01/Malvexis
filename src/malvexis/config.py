"""Runtime configuration. Secrets come from environment variables or a local .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv is a normal dependency, but don't crash if it is missing
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB: larger files get hashes + type only


def _opt_path(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value).expanduser() if value else None


@dataclass
class Config:
    vt_api_key: str | None = None
    mb_api_key: str | None = None  # abuse.ch Auth-Key
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "malvexis")
    cache_ttl: int = 24 * 3600  # seconds
    rules_dirs: list[Path] = field(default_factory=list)  # YARA
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    http_timeout: int = 15
    use_cache: bool = True
    # external analysis tools (all optional)
    capa_rules_dir: Path | None = None  # clone of github.com/mandiant/capa-rules
    capa_sigs_dir: Path | None = None  # the sigs/ folder of github.com/mandiant/capa
    clamav_db_dir: Path | None = None  # optional custom ClamAV database dir (default: system one)
    tool_timeout: int = 300  # seconds per external tool run

    @classmethod
    def from_env(cls, rules_dirs: list[str | Path] | None = None) -> "Config":
        if load_dotenv is not None:
            load_dotenv()

        cfg = cls(
            vt_api_key=os.getenv("VT_API_KEY") or None,
            mb_api_key=os.getenv("MB_API_KEY") or None,
            capa_rules_dir=_opt_path("CAPA_RULES_DIR"),
            capa_sigs_dir=_opt_path("CAPA_SIGS_DIR"),
            clamav_db_dir=_opt_path("CLAMAV_DB_DIR"),
        )

        cache_dir = os.getenv("MALVEXIS_CACHE_DIR")
        if cache_dir:
            cfg.cache_dir = Path(cache_dir).expanduser()

        if rules_dirs:
            cfg.rules_dirs = [Path(p).expanduser() for p in rules_dirs]
        else:
            env_rules = os.getenv("MALVEXIS_RULES_DIR")
            if env_rules:
                cfg.rules_dirs = [Path(p).expanduser() for p in env_rules.split(os.pathsep) if p]
            elif Path("rules").is_dir():
                cfg.rules_dirs = [Path("rules")]
        return cfg
