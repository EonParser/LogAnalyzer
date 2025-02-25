from dataclasses import dataclass
from typing import Optional

@dataclass
class AnalyzerConfig:
    """Configuration for log analyzer"""
    max_workers: int = 4
    chunk_size: int = 8192
    max_errors: int = 1000
    ignore_blank_lines: bool = True
    encoding: str = 'utf-8'
    log_level: str = 'INFO'
    timeout: int = 30