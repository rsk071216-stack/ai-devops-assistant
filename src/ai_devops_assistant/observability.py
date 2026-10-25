"""Structured JSON logging. Logs never contain log content or secrets, only metadata."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

LOGGER_NAME = "aida"
_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED:
                payload[key] = value
        return json.dumps(payload, default=str, sort_keys=False)


def configure_logging(level: str = "WARNING", *, json_logs: bool = True) -> logging.Logger:
    """Configure the ``aida`` logger on stderr (stdout is reserved for the result)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json_logs else logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def log_event(event: str, **fields: Any) -> None:
    get_logger().info(event, extra=fields)
