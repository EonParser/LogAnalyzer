import re
from datetime import datetime
from typing import Any, Dict, Optional

from .base import BaseParser, LogEntry, ParserError


class NginxAccessLogParser(BaseParser):
    """Parser for Nginx access logs"""

    # Default Nginx log format pattern
    PATTERN = (
        r"(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+"
        r"\[(?P<time_local>[\w:/]+\s[+\-]\d{4})\]\s+"
        r'"(?P<request_method>\S+)\s+(?P<request_uri>\S+)\s+'
        r'(?P<server_protocol>\S+)"\s+(?P<status>\d+)\s+'
        r'(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*?)"\s+'
        r'"(?P<http_user_agent>[^"]*?)"\s+"(?P<http_x_forwarded_for>[^"]*?)"'
    )

    def __init__(self, pattern: Optional[str] = None):
        """Initialize parser with optional custom pattern"""
        self.regex = re.compile(pattern or self.PATTERN)
        self._custom_pattern = pattern is not None

    def supports_format(self, line: str) -> bool:
        """Check if line matches Nginx access log format"""
        return bool(self.regex.match(line))

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a Nginx access log line

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        match = self.regex.match(line)
        if not match:
            raise ParserError(f"Line does not match Nginx format: {line}")

        data = match.groupdict()

        try:
            # Parse timestamp
            timestamp = datetime.strptime(data["time_local"], "%d/%b/%Y:%H:%M:%S %z")

            # Build parsed data
            parsed_data: Dict[str, Any] = {
                "remote_addr": data["remote_addr"],
                "remote_user": data["remote_user"],
                "request": {
                    "method": data["request_method"],
                    "uri": data["request_uri"],
                    "protocol": data["server_protocol"],
                },
                "status": int(data["status"]),
                "body_bytes_sent": int(data["body_bytes_sent"]),
                "http_referer": data["http_referer"],
                "http_user_agent": data["http_user_agent"],
            }

            # Add X-Forwarded-For if present
            if data["http_x_forwarded_for"]:
                parsed_data["x_forwarded_for"] = [
                    ip.strip() for ip in data["http_x_forwarded_for"].split(",")
                ]

            return LogEntry(
                timestamp=timestamp,
                level="INFO" if int(data["status"]) < 400 else "ERROR",
                message=(
                    f"{data['request_method']} {data['request_uri']} "
                    f"{data['status']} {data['body_bytes_sent']}b"
                ),
                source="nginx",
                raw_data=line,
                parsed_data=parsed_data,
                metadata={"log_type": "access", "server_type": "nginx"},
            )

        except (ValueError, KeyError) as e:
            raise ParserError(f"Error parsing Nginx log: {str(e)}") from e


class NginxErrorLogParser(BaseParser):
    """Parser for Nginx error logs"""

    PATTERN = (
        r"(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
        r"\[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): "
        r"(?P<message>.*?)(?:, client: (?P<client>\S+))?"
        r"(?:, server: (?P<server>\S+))?"
        r'(?:, request: "(?P<request>[^"]*)")?'
        r'(?:, upstream: "(?P<upstream>[^"]*)")?'
        r'(?:, host: "(?P<host>[^"]*)")?'
        r'(?:, referrer: "(?P<referrer>[^"]*)")?\s*$'
    )

    def __init__(self):
        self.regex = re.compile(self.PATTERN)

    def supports_format(self, line: str) -> bool:
        """Check if line matches Nginx error log format"""
        return bool(self.regex.match(line))

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a Nginx error log line"""
        match = self.regex.match(line)
        if not match:
            raise ParserError(f"Line does not match Nginx error format: {line}")

        data = match.groupdict()

        try:
            # Parse timestamp
            timestamp = datetime.strptime(data["time"], "%Y/%m/%d %H:%M:%S")

            # Build parsed data
            parsed_data = {"pid": int(data["pid"]), "tid": int(data["tid"])}

            # Add optional fields if present
            for field in [
                "client",
                "server",
                "request",
                "upstream",
                "host",
                "referrer",
            ]:
                if data[field]:
                    parsed_data[field] = data[field]

            return LogEntry(
                timestamp=timestamp,
                level=data["level"].upper(),
                message=data["message"],
                source="nginx",
                raw_data=line,
                parsed_data=parsed_data,
                metadata={"log_type": "error", "server_type": "nginx"},
            )

        except (ValueError, KeyError) as e:
            raise ParserError(f"Error parsing Nginx error log: {str(e)}") from e
