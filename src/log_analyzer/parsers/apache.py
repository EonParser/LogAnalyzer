import re
from datetime import datetime
from typing import Any, Dict, Optional

from .base import BaseParser, LogEntry, ParserError


class ApacheLogParser(BaseParser):
    """Parser for Apache/HTTPD access logs"""

    # Standard Apache combined log format pattern
    PATTERN = (
        r"(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[\w:/]+\s[+\-]\d{4})\] "
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d+) (?P<bytes>\S+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
    )

    def __init__(self):
        self.regex = re.compile(self.PATTERN)

    def supports_format(self, line: str) -> bool:
        """Check if line matches Apache log format"""
        return bool(self.regex.match(line))

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse an Apache log line into structured data

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        match = self.regex.match(line)
        if not match:
            raise ParserError(f"Line does not match Apache format: {line}")

        data = match.groupdict()

        try:
            # Parse timestamp
            timestamp = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")

            # Convert bytes to int, handling '-' for 0 bytes
            bytes_sent = int(data["bytes"]) if data["bytes"] != "-" else 0

            parsed_data: Dict[str, Any] = {
                "ip_address": data["ip"],
                "method": data["method"],
                "path": data["path"],
                "protocol": data["protocol"],
                "status_code": int(data["status"]),
                "bytes_sent": bytes_sent,
                "referer": data["referer"],
                "user_agent": data["user_agent"],
            }

            return LogEntry(
                timestamp=timestamp,
                level="INFO" if int(data["status"]) < 400 else "ERROR",
                message=f"{data['method']} {data['path']} {data['status']}",
                source="apache",
                raw_data=line,
                parsed_data=parsed_data,
                metadata={"log_type": "access", "server_type": "apache"},
            )

        except (ValueError, KeyError) as e:
            raise ParserError(f"Error parsing Apache log: {str(e)}") from e


class ApacheErrorLogParser(BaseParser):
    """Parser for Apache/HTTPD error logs"""

    PATTERN = r"\[(?P<timestamp>.*?)\] \[(?P<level>\w+)\] (?P<message>.*)"

    def __init__(self):
        self.regex = re.compile(self.PATTERN)

    def supports_format(self, line: str) -> bool:
        """Check if line matches Apache error log format"""
        return bool(self.regex.match(line))

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse an Apache error log line

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        match = self.regex.match(line)
        if not match:
            raise ParserError(f"Line does not match Apache error format: {line}")

        data = match.groupdict()

        try:
            # Parse timestamp
            timestamp = datetime.strptime(data["timestamp"], "%a %b %d %H:%M:%S.%f %Y")

            return LogEntry(
                timestamp=timestamp,
                level=data["level"],
                message=data["message"],
                source="apache",
                raw_data=line,
                parsed_data={"error_message": data["message"]},
                metadata={"log_type": "error", "server_type": "apache"},
            )

        except (ValueError, KeyError) as e:
            raise ParserError(f"Error parsing Apache error log: {str(e)}") from e
