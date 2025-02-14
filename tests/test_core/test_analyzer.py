from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from log_analyzer.core.analyzer import LogAnalyzer
from log_analyzer.parsers.base import BaseParser, LogEntry, ParserFactory
from log_analyzer.processors.pipeline import Pipeline


class MockParser(BaseParser):
    """Mock parser for testing"""

    def __init__(self, should_succeed=True):
        self.should_succeed = should_succeed
        self.parse_count = 0

    def supports_format(self, line: str) -> bool:
        return True

    def parse_line(self, line: str) -> LogEntry:
        self.parse_count += 1
        if not self.should_succeed:
            raise ValueError("Mock parsing error")
        return LogEntry(
            timestamp=datetime.now(),
            level="INFO",
            message=line,
            source="mock",
            raw_data=line,
            parsed_data={},
            metadata={},
        )


@pytest.fixture
def analyzer():
    """Create analyzer instance with mock parser"""
    parser_factory = ParserFactory()
    parser_factory.register_parser("mock", MockParser)
    return LogAnalyzer(parser_factory=parser_factory)


@pytest.fixture
def sample_log_file(tmp_path):
    """Create a temporary log file"""
    log_file = tmp_path / "test.log"
    log_file.write_text("line1\nline2\nline3\n")
    return log_file


def test_analyze_file_basic(analyzer, sample_log_file):
    """Test basic file analysis"""
    results = analyzer.analyze_file(sample_log_file, parser_name="mock")

    assert results["total_entries"] == 3
    assert results["errors"]["count"] == 0


def test_analyze_file_with_errors(analyzer, sample_log_file):
    """Test handling of parser errors"""
    analyzer.parser_factory.register_parser(
        "failing_mock", lambda: MockParser(should_succeed=False)
    )

    results = analyzer.analyze_file(sample_log_file, parser_name="failing_mock")

    assert results["total_entries"] == 0
    assert results["errors"]["count"] == 3


def test_analyze_file_with_pipeline(analyzer, sample_log_file):
    """Test analysis with processing pipeline"""
    pipeline = Pipeline()
    processed_entries = []

    def mock_processor(entry):
        processed_entries.append(entry)
        return entry

    pipeline.add_preprocessor(mock_processor)

    analyzer.analyze_file(sample_log_file, parser_name="mock", pipeline=pipeline)

    assert len(processed_entries) == 3


def test_analyze_directory(analyzer, tmp_path):
    """Test directory analysis"""
    # Create multiple log files
    for i in range(3):
        log_file = tmp_path / f"test{i}.log"
        log_file.write_text(f"file{i}_line1\nfile{i}_line2\n")

    results = analyzer.analyze_directory(tmp_path, pattern="*.log", parser_name="mock")

    assert results["total_entries"] == 6
    assert results["errors"]["count"] == 0


@pytest.mark.asyncio
async def test_analyze_file_async(analyzer, sample_log_file):
    """Test asynchronous file analysis"""
    results = await analyzer.analyze_file_async(sample_log_file, parser_name="mock")

    assert results["total_entries"] == 3
    assert results["errors"]["count"] == 0


def test_auto_parser_detection(analyzer, sample_log_file):
    """Test automatic parser detection"""

    class DetectableParser(MockParser):
        def supports_format(self, line: str) -> bool:
            return line.startswith("detectable")

    analyzer.parser_factory.register_parser("detectable", DetectableParser)

    # Create file with detectable format
    log_file = Path(sample_log_file)
    log_file.write_text("detectable_line1\ndetectable_line2\n")

    results = analyzer.analyze_file(log_file)  # No parser specified
    assert results["total_entries"] == 2


def test_analyzer_metrics(analyzer, sample_log_file):
    """Test metrics collection"""
    results = analyzer.analyze_file(sample_log_file, parser_name="mock")

    assert "time_range" in results
    assert "start" in results["time_range"]
    assert "end" in results["time_range"]
    assert "duration_seconds" in results["time_range"]
    assert "entries_per_second" in results


def test_concurrent_processing(analyzer, tmp_path):
    """Test concurrent file processing"""
    # Create multiple large log files
    for i in range(5):
        log_file = tmp_path / f"test{i}.log"
        log_file.write_text("\n".join(f"line{j}" for j in range(1000)))

    results = analyzer.analyze_directory(
        tmp_path, pattern="*.log", parser_name="mock", max_workers=3
    )

    assert results["total_entries"] == 5000
    assert results["errors"]["count"] == 0


def test_error_handling(analyzer, sample_log_file):
    """Test various error handling scenarios"""
    # Test non-existent file
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file(Path("nonexistent.log"))

    # Test invalid parser name
    with pytest.raises(KeyError):
        analyzer.analyze_file(sample_log_file, parser_name="invalid")

    # Test directory with no matching files
    results = analyzer.analyze_directory(tmp_path, pattern="nonexistent*.log")
    assert results["total_entries"] == 0
