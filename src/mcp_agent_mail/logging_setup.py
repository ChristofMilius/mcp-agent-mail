"""
logging_setup.py — Centralized logging configuration
=====================================================
Configures two handlers:
  1. StreamHandler (stderr)   — INFO level, visible in the harness console.
  2. RotatingFileHandler      — DEBUG level, written to logs/mcp_server.log.
                                 Rotates at 5 MB, keeps 5 backups.
                                 Full tracebacks (exc_info=True) go here.

Security notes:
  - SecretString values never appear in log output (enforced by __str__/__repr__).
  - The log file itself is NOT encrypted. Do not store it on a shared volume.
    If at-rest encryption is required, point LOGS_DIR at an encrypted volume.
  - File permissions are set to owner-read/write only (0o600) on POSIX.
    Windows does not support chmod — rely on NTFS ACLs.

Call setup_logging(cfg) exactly once, before any other module emits records.
"""

from __future__ import annotations

import logging
import os
import stat
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Format does NOT include %(pathname)s or %(lineno)d in the console handler;
# avoids leaking internal file structure to the harness's stderr.
_FILE_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_CONSOLE_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"

_LOG_FILENAME = "mcp_agent_mail.log"
_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
_BACKUP_COUNT = 5  # keep mcp_agent_mail.log through .log.5


def setup_logging(logs_dir: str) -> Path:
    """
    Configure the root logger with a console handler and a rotating file handler.

    Args:
        logs_dir: Path to the directory where log files are written.
                  Created if it does not exist.

    Returns:
        The resolved path to the log file.

    Raises:
        OSError: If the log directory cannot be created or the log file cannot
                 be opened. The server refuses to start rather than running
                 without an audit trail.
    """
    log_dir = Path(logs_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(log_dir, stat.S_IRWXU)  # 0o700 — owner only
    except (AttributeError, NotImplementedError):
        pass  # Windows — rely on NTFS ACLs

    log_file = log_dir / _LOG_FILENAME

    root_logger = logging.getLogger()

    # Avoid duplicate handlers if called more than once (e.g. in tests).
    if any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
        return log_file

    root_logger.setLevel(logging.DEBUG)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FILE_FORMAT))

    try:
        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except (AttributeError, NotImplementedError, FileNotFoundError):
        pass

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT))

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logging.getLogger(__name__).info(
        "[logging] Log file: %s (rotating, max %d MB x %d backups)",
        log_file,
        _MAX_BYTES // (1024 * 1024),
        _BACKUP_COUNT,
    )

    return log_file


__all__ = ["setup_logging"]
