from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from ...parsers.base import BaseParser
from ...processors.pipeline import Pipeline

class BaseAnalyzer(ABC):
    """Base class for all analyzers"""
    
    @abstractmethod
    def analyze_file(
        self, 
        file_path: Path,
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> Dict[str, Any]:
        """Analyze a single file"""
        pass

    @abstractmethod
    def analyze_directory(
        self,
        directory: Path,
        pattern: str = "*.log*",
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> Dict[str, Any]:
        """Analyze all files in a directory"""
        pass