from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

@dataclass
class AnalysisError:
    message: str
    line_number: Optional[int] = None
    timestamp: datetime = datetime.now()

@dataclass
class FileAnalysisResults:
    file_path: str
    total_entries: int
    successful_entries: int
    errors: List[AnalysisError]
    metrics: Dict[str, Any]
    duration: float
    parser_used: str

@dataclass
class DirectoryAnalysisResults:
    directory: str
    total_files: int
    successful_files: int
    failed_files: int
    file_results: List[FileAnalysisResults]
    combined_metrics: Dict[str, Any]
    errors: List[AnalysisError]
    duration: float