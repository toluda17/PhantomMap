"""
logger.py

Centralised logger setup for PhantomMap. Every module calls get_logger(__name__)
rather than configuring logging independently. This gives consistent formatting
across the pipeline and respects the LOG_LEVEL set in config.
"""

import logging
from phantommap.config import LOG_LEVEL


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger for the given module name.

    Usage in any module:
        from phantommap.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Surface mapper initialised")
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    return logger
