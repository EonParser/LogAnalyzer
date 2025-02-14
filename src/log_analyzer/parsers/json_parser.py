import json
from datetime import datetime
from typing import Any, Dict, Optional

from .base import BaseParser, LogEntry, ParserError


class JSONLogParser(BaseParser):
    """Parser for JSON format logs"""

    REQUIRED_FIELDS = {"timestamp", "level", "message"}
    TIMESTAMP_FORMATS = [
        "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO format with microseconds
        "%Y-%m-%dT%H:%M:%SZ",  # ISO format without microseconds
        "%Y-%m-%d %H:%M:%S.%f",  # Common datetime format with microseconds
        "%Y-%m-%d %H:%M:%S",  # Common datetime format without microseconds
    ]

    def supports_format(self, line: str) -> bool:
        """Check if line is valid JSON and has required fields"""
        try:
            data = json.loads(line)
            return all(field in data for field in self.REQUIRED_FIELDS)
        except (json.JSONDecodeError, TypeError):
            return False

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a JSON log line into structured data

        Args:
            line: Raw JSON log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            raise ParserError(f"Invalid JSON: {str(e)}") from e

        # Validate required fields
        missing_fields = self.REQUIRED_FIELDS - set(data.keys())
        if missing_fields:
            raise ParserError(f"Missing required fields: {', '.join(missing_fields)}")

        # Parse timestamp
        timestamp = self._parse_timestamp(data["timestamp"])

        # Extract known fields
        level = str(data.get("level", "")).upper()
        message = str(data["message"])
        source = str(data.get("source", "unknown"))

        # Remove known fields from parsed_data
        parsed_data = data.copy()
        for field in ["timestamp", "level", "message", "source"]:
            parsed_data.pop(field, None)

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            source=source,
            raw_data=line,
            parsed_data=parsed_data,
            metadata={
                "log_type": "json",
                "structure_version": data.get("version", "1.0"),
            },
        )

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Try parsing timestamp with multiple formats

        Args:
            timestamp_str: Timestamp string to parse

        Returns:
            Parsed datetime object

        Raises:
            ParserError: If timestamp cannot be parsed
        """
        for format_str in self.TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(timestamp_str, format_str)
            except ValueError:
                continue

        raise ParserError(
            f"Unable to parse timestamp: {timestamp_str}. "
            f"Supported formats: {', '.join(self.TIMESTAMP_FORMATS)}"
        )


class StructuredJSONLogParser(JSONLogParser):
    """Parser for structured JSON logs with specific schema"""

    def __init__(self, schema: Dict[str, Any]):
        """Initialize parser with schema

        Args:
            schema: Dictionary defining expected structure and types
        """
        super().__init__()
        self.schema = schema

    def validate_schema(self, data: Dict[str, Any]) -> None:
        """Validate data against schema

        Args:
            data: Parsed JSON data to validate

        Raises:
            ParserError: If data doesn't match schema
        """
        for field, expected_type in self.schema.items():
            if field not in data:
                raise ParserError(f"Missing required field: {field}")

            actual_value = data[field]
            if not isinstance(actual_value, expected_type):
                raise ParserError(
                    f"Invalid type for {field}. "
                    f"Expected {expected_type.__name__}, "
                    f"got {type(actual_value).__name__}"
                )

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse and validate structured JSON log line"""
        entry = super().parse_line(line)
        if entry:
            try:
                self.validate_schema(json.loads(line))
            except ParserError as e:
                raise ParserError(f"Schema validation failed: {str(e)}") from e
        return entry
