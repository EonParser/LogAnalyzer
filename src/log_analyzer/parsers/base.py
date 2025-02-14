import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class LogEntry:
    """Standardized log entry across all parser types"""

    timestamp: datetime
    level: str
    message: str
    source: str
    raw_data: str
    parsed_data: Dict[str, Any]
    metadata: Dict[str, Any]


class BaseParser(ABC):
    """Abstract base class for all log parsers"""

    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single line of log text into a structured LogEntry object

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry object if parsing successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        pass

    @abstractmethod
    def supports_format(self, line: str) -> bool:
        """Check if this parser supports the given log format

        Args:
            line: Sample log line to check

        Returns:
            True if this parser can handle the format, False otherwise
        """
        pass


class ParserError(Exception):
    """Raised when a log line cannot be parsed"""

    pass


class ParserFactory:
    """Factory class for creating parser instances"""

    def __init__(self):
        self._parsers: Dict[str, type[BaseParser]] = {}

    def register_parser(self, name: str, parser_class: type[BaseParser]) -> None:
        """Register a new parser class

        Args:
            name: Unique name for the parser
            parser_class: Parser class to register
        """
        self._parsers[name] = parser_class

    def get_parser(self, name: str) -> BaseParser:
        """Get a parser instance by name

        Args:
            name: Name of the parser to get

        Returns:
            Instance of the requested parser

        Raises:
            KeyError: If parser name not found
        """
        parser_class = self._parsers[name]
        return parser_class()

    def detect_parser(self, sample_line: str) -> Optional[BaseParser]:
        """Auto-detect appropriate parser for a log line

        Args:
            sample_line: Sample log line to analyze

        Returns:
            Parser instance that can handle the format, or None if no parser found
        """
        # Try JSON first (most strict format)
        try:
            import json

            json.loads(sample_line)
            return self.get_parser("json")
        except json.JSONDecodeError:
            pass

        # Try all registered parsers
        for parser_name, parser_class in self._parsers.items():
            try:
                parser = parser_class()
                if parser.supports_format(sample_line):
                    return parser
            except:
                continue

        # Default to a simple line parser if nothing else works
        from ..parsers.base import SimpleLineParser

        return SimpleLineParser()


class SimpleLineParser(BaseParser):
    """Simple parser that treats each line as a log entry"""

    def supports_format(self, line: str) -> bool:
        """Any line is supported"""
        return True

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse line as a simple log entry"""
        try:
            # Try to extract timestamp and level if present
            timestamp_patterns = [
                r"\[([\d/\w:\s+\-]+)\]",  # [22/Dec/2016:16:18:09 +0300]
                r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",  # 2016-12-22 16:18:09
            ]

            timestamp = None
            for pattern in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    try:
                        timestamp_str = match.group(1)
                        # Try common timestamp formats
                        for fmt in ["%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"]:
                            try:
                                timestamp = datetime.strptime(timestamp_str, fmt)
                                break
                            except ValueError:
                                continue
                    except:
                        pass
                if timestamp:
                    break

            # Try to detect log level
            level = "INFO"  # default level
            level_patterns = {
                "ERROR": r"\b(ERROR|CRITICAL|FATAL)\b",
                "WARNING": r"\bWARN(ING)?\b",
                "INFO": r"\bINFO\b",
                "DEBUG": r"\bDEBUG\b",
            }

            for lvl, pattern in level_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    level = lvl
                    break

            return LogEntry(
                timestamp=timestamp or datetime.now(),
                level=level,
                message=line,
                source="generic",
                raw_data=line,
                parsed_data={},
                metadata={"parser": "simple"},
            )

        except Exception as e:
            raise ParserError(f"Error parsing line: {str(e)}") from e
