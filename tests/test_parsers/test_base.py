from datetime import datetime

import pytest

from log_analyzer.parsers.base import BaseParser, LogEntry, ParserError, ParserFactory


class SimpleParser(BaseParser):
    """Simple parser implementation for testing"""

    def __init__(self, format_pattern="test"):
        self.format_pattern = format_pattern

    def supports_format(self, line: str) -> bool:
        return line.startswith(self.format_pattern)

    def parse_line(self, line: str) -> LogEntry:
        if not self.supports_format(line):
            raise ParserError(f"Unsupported format: {line}")
        return LogEntry(
            timestamp=datetime.now(),
            level="INFO",
            message=line,
            source="test",
            raw_data=line,
            parsed_data={},
            metadata={},
        )


class FailingParser(BaseParser):
    """Parser that always fails for testing error handling"""

    def supports_format(self, line: str) -> bool:
        return True

    def parse_line(self, line: str) -> LogEntry:
        raise ParserError("Simulated parsing failure")


def test_log_entry_creation():
    """Test LogEntry creation and validation"""
    timestamp = datetime.now()
    entry = LogEntry(
        timestamp=timestamp,
        level="INFO",
        message="Test message",
        source="test",
        raw_data="raw log line",
        parsed_data={"key": "value"},
        metadata={"meta": "data"},
    )

    assert entry.timestamp == timestamp
    assert entry.level == "INFO"
    assert entry.message == "Test message"
    assert entry.source == "test"
    assert entry.raw_data == "raw log line"
    assert entry.parsed_data == {"key": "value"}
    assert entry.metadata == {"meta": "data"}


def test_parser_factory():
    """Test ParserFactory registration and retrieval"""
    factory = ParserFactory()

    # Register parsers
    factory.register_parser("simple", SimpleParser)
    factory.register_parser("failing", FailingParser)

    # Get parser instances
    simple_parser = factory.get_parser("simple")
    failing_parser = factory.get_parser("failing")

    assert isinstance(simple_parser, SimpleParser)
    assert isinstance(failing_parser, FailingParser)

    # Test invalid parser name
    with pytest.raises(KeyError):
        factory.get_parser("nonexistent")


def test_parser_factory_detection():
    """Test parser auto-detection"""
    factory = ParserFactory()

    # Register parsers with different patterns
    factory.register_parser("parser1", lambda: SimpleParser(format_pattern="format1"))
    factory.register_parser("parser2", lambda: SimpleParser(format_pattern="format2"))

    # Test detection
    parser = factory.detect_parser("format1_test_line")
    assert isinstance(parser, SimpleParser)
    assert parser.format_pattern == "format1"

    parser = factory.detect_parser("format2_test_line")
    assert isinstance(parser, SimpleParser)
    assert parser.format_pattern == "format2"

    # Test no matching parser
    assert factory.detect_parser("unknown_format") is None


def test_parser_error():
    """Test ParserError handling"""
    parser = SimpleParser()

    # Test successful parsing
    entry = parser.parse_line("test_line")
    assert isinstance(entry, LogEntry)

    # Test parsing error
    with pytest.raises(ParserError):
        parser.parse_line("invalid_line")


def test_log_entry_validation():
    """Test LogEntry validation"""
    timestamp = datetime.now()

    # Test invalid level
    with pytest.raises(ValueError):
        LogEntry(
            timestamp=timestamp,
            level="INVALID_LEVEL",
            message="Test",
            source="test",
            raw_data="raw",
            parsed_data={},
            metadata={},
        )

    # Test missing required fields
    with pytest.raises(TypeError):
        LogEntry(timestamp=timestamp, level="INFO")  # Missing required fields


def test_parser_factory_registration():
    """Test parser registration edge cases"""
    factory = ParserFactory()

    # Test registering same parser twice
    factory.register_parser("test", SimpleParser)
    factory.register_parser("test", SimpleParser)  # Should override

    # Test registering invalid parser class
    class InvalidParser:  # Doesn't inherit from BaseParser
        pass

    with pytest.raises(TypeError):
        factory.register_parser("invalid", InvalidParser)


def test_log_entry_immutability():
    """Test LogEntry immutability"""
    entry = LogEntry(
        timestamp=datetime.now(),
        level="INFO",
        message="Test",
        source="test",
        raw_data="raw",
        parsed_data={"key": "value"},
        metadata={"meta": "data"},
    )

    # Ensure parsed_data and metadata are copied
    entry.parsed_data["new_key"] = "new_value"
    entry.metadata["new_meta"] = "new_data"

    # Original data should be unchanged
    assert "new_key" not in entry.parsed_data
    assert "new_meta" not in entry.metadata


def test_parser_factory_thread_safety():
    """Test ParserFactory thread safety"""
    import threading

    factory = ParserFactory()
    errors = []

    def register_parser():
        try:
            factory.register_parser(f"parser_{threading.get_ident()}", SimpleParser)
        except Exception as e:
            errors.append(e)

    # Create multiple threads
    threads = [threading.Thread(target=register_parser) for _ in range(10)]

    # Start and join threads
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(factory._parsers) == 10
