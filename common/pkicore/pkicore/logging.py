"""Structured JSON logging with automatic secret redaction."""
from __future__ import annotations

import logging
import re
import sys

import structlog

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|secret|token|pin|private_key|api[_-]?key)\s*=\s*[^&\s]+"),
]


def _redact(_, __, event_dict):
    for key in ("password", "secret", "token", "pin", "private_key", "api_key", "vault_token"):
        if key in event_dict:
            event_dict[key] = "***REDACTED***"
    msg = event_dict.get("event")
    if isinstance(msg, str):
        for pattern in _SECRET_PATTERNS:
            msg = pattern.sub(lambda m: m.group(0).split("=")[0] + "=***REDACTED***", msg)
        event_dict["event"] = msg
    return event_dict


def configure_logging(service_name: str, level: str = "INFO", json_output: bool = True) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _redact,
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.processors.JSONRenderer()
            if json_output
            else structlog.dev.ConsoleRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    structlog.contextvars.bind_contextvars(service=service_name)


def get_logger(name: str | None = None):
    return structlog.get_logger(name)
