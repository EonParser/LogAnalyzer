from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..parsers.base import BaseParser, LogEntry, ParserFactory
from ..processors.pipeline import Pipeline
from .metrics import MetricsCollector
from .reader import LogReader

class LogAnalyzer:
    """Main log analyzer class coordinating parsing and analysis"""

    def __init__(
        self, 
        parser_factory: Optional[ParserFactory] = None, 
        max_workers: int = 4
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
        self.logger = logging.getLogger(__name__)

    def register_processor(self, processor: Callable[[LogEntry], None]) -> None:
        """Register a log entry processor

        Args:
            processor: Callback function to process each log entry
        """
        self._processors.append(processor)

    def _get_parser(self, parser_name: Optional[str], sample_line: str) -> Optional[BaseParser]:
        """Get appropriate parser for the file based on name or content

        Args:
            parser_name: Optional specific parser name to use
            sample_line: Sample line from file for auto-detection

        Returns:
            Appropriate parser instance or None if no suitable parser found
        """
        try:
            if parser_name:
                return self.parser_factory.get_parser(parser_name)

            # Try all registered parsers
            for name, parser_class in self.parser_factory._parsers.items():
                try:
                    parser = parser_class()
                    if parser.supports_format(sample_line):
                        self.logger.info(f"Auto-detected parser: {name}")
                        return parser
                except Exception as e:
                    self.logger.debug(f"Parser {name} check failed: {str(e)}")
                    continue

            return None
        except Exception as e:
            self.logger.error(f"Error getting parser: {str(e)}")
            return None

    def analyze_file(
        self,
        file_path: Path,
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> Dict[str, Any]:
        """Analyze a single log file

        Args:
            file_path: Path to log file
            parser_name: Optional specific parser to use
            pipeline: Optional processing pipeline

        Returns:
            Dictionary containing analysis results

        Raises:
            ValueError: If file cannot be analyzed
        """
        self.logger.info(f"Starting analysis of {file_path}")
        self.metrics.reset()
        entries = []
        errors = []

        try:
            # Read all lines
            lines = list(self.reader.read_lines(file_path))
            if not lines:
                self.logger.warning(f"Empty file: {file_path}")
                return {
                    "entries": [],
                    "total_entries": 0,
                    "errors": [],
                    "metrics": self.metrics.get_results()
                }

            # Get appropriate parser
            parser = self._get_parser(parser_name, lines[0])
            if not parser:
                raise ValueError(f"No suitable parser found for {file_path}")

            # Process all lines
            for line_number, line in enumerate(lines, 1):
                try:
                    line = line.strip()
                    if not line:
                        continue

                    entry = parser.parse_line(line.strip())
                    if entry:
                        # Apply processors
                        for processor in self._processors:
                            processor(entry)

                        # Apply pipeline if present
                        if pipeline:
                            entry = pipeline.process(entry)
                            if not entry:  # Entry was filtered out
                                continue

                        if entry:  # Entry wasn't filtered out
                            entries.append(entry)
                            self.metrics.process_entry(entry)

                except Exception as e:
                    self.logger.warning(f"Error processing line {line_number}: {str(e)}")
                    self.metrics.record_error(f"Line {line_number}: {str(e)}")
                    continue

            # Finalize processing
            self.metrics.finish_processing()
            
            # Get errors safely
            errors = self.metrics.get_errors() if hasattr(self.metrics, 'get_errors') else []

            results = {
                "entries": entries,
                "total_entries": len(entries),
                "file_path": str(file_path),
                "metrics": self.metrics.get_results(),
                "errors": errors
            }

            self.logger.info(
                f"Completed analysis of {file_path}: "
                f"{len(entries)} entries processed, "
                f"{len(errors)} errors"
            )

            return results

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}", exc_info=True)
            return {
                "entries": entries,
                "total_entries": len(entries),
                "file_path": str(file_path),
                "errors": [str(e)],
                "metrics": self.metrics.get_results()
            }

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
        self.logger.info(f"Starting directory analysis: {directory}")
        
        results = {
            'files': [],
            'errors': [],
            'summary': {
                'total_files': 0,
                'successful': 0,
                'failed': 0
            },
            'combined_metrics': None
        }

        try:
            # Get list of files
            files = list(directory.glob(pattern))
            results['summary']['total_files'] = len(files)
            
            if not files:
                self.logger.warning(f"No files found in {directory} matching pattern {pattern}")
                return results

            # Process files in parallel
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_path = {
                    executor.submit(self.analyze_file, path, parser_name, pipeline): path 
                    for path in files
                }

                # Collect results
                combined_metrics = MetricsCollector()
                
                for future in future_to_path:
                    path = future_to_path[future]
                    try:
                        file_results = future.result()
                        results['files'].append({
                            'path': str(path),
                            'results': file_results
                        })
                        results['summary']['successful'] += 1
                        
                        # Merge metrics
                        if 'metrics' in file_results:
                            combined_metrics.merge(file_results['metrics'])
                            
                    except Exception as e:
                        self.logger.error(f"Error processing {path}: {str(e)}")
                        results['errors'].append({
                            'path': str(path),
                            'error': str(e)
                        })
                        results['summary']['failed'] += 1

            # Add combined metrics
            results['combined_metrics'] = combined_metrics.get_results()
            
            self.logger.info(
                f"Directory analysis complete: "
                f"{results['summary']['successful']} files successful, "
                f"{results['summary']['failed']} files failed"
            )

            return results

        except Exception as e:
            self.logger.error(f"Error analyzing directory {directory}: {str(e)}", exc_info=True)
            raise ValueError(f"Error analyzing directory: {str(e)}")

    def _analyze_with_parser(self, file_path: Path, parser: BaseParser, pipeline: Optional[Pipeline] = None) -> Dict[str, Any]:
        """Analyze a file using a specific parser

        Args:
            file_path: Path to log file
            parser: Parser instance to use
            pipeline: Optional processing pipeline

        Returns:
            Analysis results
        """
        self.metrics.reset()
        
        try:
            for line in self.reader.read_lines(file_path):
                try:
                    entry = parser.parse_line(line.strip())
                    if entry:
                        # Apply processors
                        for processor in self._processors:
                            processor(entry)

                        if pipeline:
                            entry = pipeline.process(entry)
                            if not entry:  # Entry was filtered out
                                continue
                                
                        self.metrics.process_entry(entry)
                        
                except Exception as e:
                    self.metrics.record_error(str(e))
                    
        finally:
            self.metrics.finish_processing()
            return self.metrics.get_results()