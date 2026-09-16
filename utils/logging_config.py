"""
Centralized logging configuration for the TA symbolic execution framework.

Usage:
    from utils.logging_config import get_logger, setup_logging
    
    # In main.py, call setup_logging() once with CLI args
    setup_logging(log_level="INFO", log_file="output.log")
    
    # In any module, get a logger
    logger = get_logger(__name__)
    logger.info("Message")
"""

import logging
import sys
from typing import Optional

# Default format for log messages
LOG_FORMAT = "[%(name)s] %(message)s"
LOG_FORMAT_WITH_LEVEL = "[%(levelname)s] [%(name)s] %(message)s"

# Global flag to track if logging has been set up
_logging_configured = False


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    include_level: bool = False,
) -> None:
    """
    Configure the root logger for the framework.
    
    This should be called once at application startup (in main.py).
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to a log file. If provided, logs are written
                  to both stdout and the file.
        include_level: If True, include the log level in the format string
    """
    global _logging_configured
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove any existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Choose format based on preference
    log_format = LOG_FORMAT_WITH_LEVEL if include_level else LOG_FORMAT
    formatter = logging.Formatter(log_format)
    
    # Always add stdout handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(numeric_level)
    stdout_handler.setFormatter(formatter)
    root_logger.addHandler(stdout_handler)
    
    # Optionally add file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        root_logger.info(f"Logging to file: {log_file}")
    
    # Suppress noisy third-party loggers
    logging.getLogger("angr").setLevel(logging.WARNING)
    logging.getLogger("claripy").setLevel(logging.WARNING)
    logging.getLogger("cle").setLevel(logging.WARNING)
    logging.getLogger("pyvex").setLevel(logging.WARNING)
    logging.getLogger("archinfo").setLevel(logging.WARNING)
    
    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given module name.
    
    Args:
        name: Usually __name__ of the calling module
        
    Returns:
        A configured Logger instance
    """
    # If logging hasn't been configured yet, set up a basic config
    # This ensures logging works even if setup_logging() wasn't called
    if not _logging_configured:
        setup_logging("INFO")
    
    return logging.getLogger(name)

