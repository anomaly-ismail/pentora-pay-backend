"""
Yapısal loglama — structlog + rich.
ISO 27001 A.12.4 (Log Yönetimi) ve OWASP A09 (Security Logging) uyumlu.

Her log kaydı şunları içerir:
  - timestamp (ISO-8601 UTC)
  - request_id (UUID)
  - level
  - event
  - caller (modül:satır)
"""
import logging
import sys

import structlog
from rich.logging import RichHandler

from app.core.config import get_settings


def _add_app_context(logger, method_name, event_dict):
    """Her log kaydına uygulama sabit alanlarını ekler."""
    settings = get_settings()
    event_dict["app"] = settings.app_name
    event_dict["env"] = settings.app_env
    event_dict["version"] = settings.app_version
    return event_dict


def configure_logging() -> None:
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ),
        _add_app_context,
    ]

    if settings.log_format == "json":
        # Üretim: makine okunabilir JSON
        renderer = structlog.processors.JSONRenderer()
        handler = logging.StreamHandler(sys.stdout)
    else:
        # Geliştirme: renkli, okunabilir çıktı
        renderer = structlog.dev.ConsoleRenderer()
        handler = RichHandler(rich_tracebacks=True, markup=True)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Üçüncü taraf gürültüsünü bastır
    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).propagate = False


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    return structlog.get_logger(name)
