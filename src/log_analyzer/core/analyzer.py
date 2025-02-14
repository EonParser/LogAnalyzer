from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..parsers.base import BaseParser, LogEntry, ParserFactory
from ..processors.pipeline import Pipeline
from .metrics import MetricsCollector
from .reader import LogReader, MultiFileReader


class LogAnalyzer:
    """Main log analyzer class coordinating parsing and analysis"""

    def __init__(
        self, parser_factory: Optional[ParserFactory] = None, max_workers: int = 4
    ):
        """Initialize the log analyzer

        Args:
            parser_factory: Factory for creating log parsers
            max_workers: Maximum number of worker threads
        """
        self.parser_factory = parser_factory or ParserFactory()
        self.max_workers = max_workers
        self.reader = LogReader()
        self.metrics = MetricsCollector()
        self._processors: List[Callable[[LogEntry], None]] = []

    def register_processor(self, processor: Callable[[LogEntry], None]) -> None:
        """Register a log entry processor

        Args:
            processor: Callback function to process each log entry
        """
        self._processors.append(processor)

    def analyze_file(
        self,
        file_path: Path,
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None,
    ) -> Dict[str, Any]:
        """Analyze a single log file

        Args:
            file_path: Path to log file
            parser_name: Name of parser to use, or None for auto-detect
            pipeline: Optional processing pipeline

        Returns:
            Dictionary of analysis results

        Raises:
            ValueError: If no suitable parser found
        """
        # Get first line to detect format if needed
        first_line = next(self.reader.read_lines(file_path))

        parser = (
            self.parser_factory.get_parser(parser_name)
            if parser_name
            else self.parser_factory.detect_parser(first_line)
        )

        if not parser:
            raise ValueError(f"No suitable parser found for {file_path}")

        return self._analyze_with_parser(file_path, parser, pipeline)

    def analyze_directory(
        self,
        directory: Path,
        pattern: str = "*.log*",
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None,
    ) -> Dict[str, Any]:
        """Analyze all matching files in a directory

        Args:
            directory: Directory to scan
            pattern: Glob pattern for matching files
            parser_name: Name of parser to use, or None for auto-detect
            pipeline: Optional processing pipeline

        Returns:
            Combined analysis results
        """
        results = defaultdict(list)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []

            for path in directory.glob(pattern):
                future = executor.submit(self.analyze_file, path, parser_name, pipeline)
                futures.append((path, future))

            for path, future in futures:
                try:
                    file_results = future.result()
                    for key, value in file_results.items():
                        results[key].append((path, value))
                except Exception as e:
                    results["errors"].append((path, str(e)))

        return dict(results)

    def _analyze_with_parser(
        self, file_path: Path, parser: BaseParser, pipeline: Optional[Pipeline] = None
    ) -> Dict[str, Any]:
        """Analyze a file using a specific parser"""
        self.metrics.reset()

        for line in self.reader.read_lines(file_path):
            try:
                entry = parser.parse_line(line)
                if entry:
                    # Process through pipeline if provided
                    if pipeline:
                        entry = pipeline.process(entry)
                        if not entry:  # Entry was filtered out
                            continue

                    self.metrics.process_entry(entry)
                    for processor in self._processors:
                        processor(entry)
            except Exception as e:
                self.metrics.record_error(str(e))

        return self.metrics.get_results()
