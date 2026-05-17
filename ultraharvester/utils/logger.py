import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler

console = Console()

def setup_logger(name: str = "ultraharvester", level: str = "INFO", log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    rich_handler = RichHandler(console=console, show_time=True, show_path=False, markup=True)
    rich_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(rich_handler)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "ultraharvester") -> logging.Logger:
    return logging.getLogger(name)
