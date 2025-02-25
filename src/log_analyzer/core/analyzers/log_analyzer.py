import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ...parsers.base import BaseParser, LogEntry, ParserFactory
from ...processors.pipeline import Pipeline
from .base import BaseAnalyzer
from .config import AnalyzerConfig
from .results import AnalysisError, FileAnalysisResults, DirectoryAnalysisResults
from ..metrics import MetricsCollector
from ..reader import LogReader

class LogAnalyzer(BaseAnalyzer):
    """Main log analyzer implementation"""

    def __init__(
        self,
        parser_factory: Optional[ParserFactory] = None,
        config: Optional[AnalyzerConfig] = None
    ):
        self.config = config or AnalyzerConfig()
        self.parser_factory = parser_factory or ParserFactory()
        self.reader = LogReader(chunk_size=self.config.chunk_size)
        self.metrics = MetricsCollector()
        self._processors: List[Callable[[LogEntry], None]] = []
        self.logger = logging.getLogger(__name__)

    def _get_parser(self, parser_name: Optional[str], sample_line: str) -> Optional[BaseParser]:
        """Get appropriate parser for the file"""
        try:
            if parser_name:
                return self.parser_factory.get_parser(parser_name)

            # Try all registered parsers
            for name, parser_class in self.parser_factory._parsers.items():
                try:
                    parser = parser_class()
                    if parser.supports_format(sample_line):
                        self.logger.info(f"Auto-detected parser: {name}")
                        return parser, name
                except Exception as e:
                    self.logger.debug(f"Parser {name} check failed: {str(e)}")
                    continue

            return None, None
        except Exception as e:
            self.logger.error(f"Error getting parser: {str(e)}")
            return None, None

    def analyze_file(
        self,
        file_path: Path,
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> FileAnalysisResults:
        """Analyze a single log file"""
        start_time = time.time()
        self.metrics.reset()
        entries = []
        errors = []
        parser = None
        parser_name_used = "unknown"

        try:
            # Read file contents
            lines = list(self.reader.read_lines(file_path))
            if not lines:
                return self._create_empty_results(file_path, "Empty file")

            # Get parser
            parser, parser_name_used = self._get_parser(parser_name, lines[0])
            if not parser:
                return self._create_empty_results(file_path, "No suitable parser found")

            # Process lines
            for line_number, line in enumerate(lines, 1):
                try:
                    line = line.strip()
                    if not line and self.config.ignore_blank_lines:
                        continue

                    entry = self._process_line(line, parser, pipeline)
                    if entry:
                        entries.append(entry)
                except Exception as e:
                    error = AnalysisError(str(e), line_number)
                    errors.append(error)
                    self.metrics.record_error(str(error))

            # Create results
            duration = time.time() - start_time
            return FileAnalysisResults(
                file_path=str(file_path),
                total_entries=len(lines),
                successful_entries=len(entries),
                errors=errors,
                metrics=self.metrics.get_results(),
                duration=duration,
                parser_used=parser_name_used
            )

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}", exc_info=True)
            return self._create_empty_results(file_path, str(e))

    def analyze_directory(
        self,
        directory: Path,
        pattern: str = "*.log*",
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> DirectoryAnalysisResults:
        """Analyze all matching files in a directory"""
        start_time = time.time()
        results = DirectoryAnalysisResults(
            directory=str(directory),
            total_files=0,
            successful_files=0,
            failed_files=0,
            file_results=[],
            combined_metrics={},
            errors=[],
            duration=0.0
        )

        try:
            files = list(directory.glob(pattern))
            results.total_files = len(files)

            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                future_to_path = {
                    executor.submit(self.analyze_file, path, parser_name, pipeline): path
                    for path in files
                }

                for future in future_to_path:
                    path = future_to_path[future]
                    try:
                        file_results = future.result()
                        results.file_results.append(file_results)
                        
                        if file_results.successful_entries > 0:
                            results.successful_files += 1
                        else:
                            results.failed_files += 1
                            
                    except Exception as e:
                        results.failed_files += 1
                        results.errors.append(
                            AnalysisError(f"Error processing {path}: {str(e)}")
                        )

            # Calculate final metrics
            results.duration = time.time() - start_time
            results.combined_metrics = self._combine_metrics(results.file_results)
            
            return results

        except Exception as e:
            self.logger.error(f"Error analyzing directory {directory}: {str(e)}", exc_info=True)
            results.errors.append(AnalysisError(str(e)))
            results.duration = time.time() - start_time
            return results

    def _process_line(
        self, 
        line: str, 
        parser: BaseParser, 
        pipeline: Optional[Pipeline]
    ) -> Optional[LogEntry]:
        """Process a single log line"""
        entry = parser.parse_line(line)
        if not entry:
            return None

        # Apply processors
        for processor in self._processors:
            processor(entry)

        # Apply pipeline
        if pipeline:
            entry = pipeline.process(entry)
            if not entry:
                return None

        self.metrics.process_entry(entry)
        return entry

    def _create_empty_results(self, file_path: Path, error_message: str) -> FileAnalysisResults:
        """Create empty results for failed analysis"""
        return FileAnalysisResults(
            file_path=str(file_path),
            total_entries=0,
            successful_entries=0,
            errors=[AnalysisError(error_message)],
            metrics=self.metrics.get_results(),
            duration=0.0,
            parser_used="none"
        )

    def _combine_metrics(self, file_results: List[FileAnalysisResults]) -> Dict[str, Any]:
        """Combine metrics from multiple files"""
        combined = MetricsCollector()
        for result in file_results:
            combined.merge(result.metrics)
        return combined.get_results()