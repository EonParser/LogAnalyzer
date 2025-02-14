from datetime import datetime

import pytest

from log_analyzer.parsers.base import ParserError
from log_analyzer.parsers.nginx import NginxAccessLogParser, NginxErrorLogParser


@pytest.fixture
def access_parser():
    return NginxAccessLogParser()


@pytest.fixture
def error_parser():
    return NginxErrorLogParser()


class TestNginxAccessLogParser:
    """Test suite for Nginx access log parser"""

    def test_valid_default_format(self, access_parser):
        """Test parsing of valid default log format"""
        log_line = '192.168.1.100 - john [10/Feb/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0" "proxy.example.com"'

        entry = access_parser.parse_line(log_line)

        assert entry.timestamp == datetime(2024, 2, 10, 13, 55, 36)
        assert entry.level == "INFO"
        assert entry.source == "nginx"
        assert entry.parsed_data["remote_addr"] == "192.168.1.100"
        assert entry.parsed_data["remote_user"] == "john"
        assert entry.parsed_data["request"]["method"] == "GET"
        assert entry.parsed_data["request"]["uri"] == "/api/users"
        assert entry.parsed_data["request"]["protocol"] == "HTTP/1.1"
        assert entry.parsed_data["status"] == 200
        assert entry.parsed_data["body_bytes_sent"] == 2326
        assert entry.parsed_data["http_referer"] == "http://example.com"
        assert entry.parsed_data["http_user_agent"] == "Mozilla/5.0"
        assert entry.parsed_data["x_forwarded_for"] == ["proxy.example.com"]

    def test_custom_log_format(self):
        """Test parsing with custom log format"""
        custom_pattern = r"(?P<remote_addr>\S+) \[(?P<time_local>[\w:/]+\s[+\-]\d{4})\] (?P<status>\d+)"
        parser = NginxAccessLogParser(pattern=custom_pattern)

        log_line = "192.168.1.100 [10/Feb/2024:13:55:36 +0000] 200"
        entry = parser.parse_line(log_line)

        assert entry.parsed_data["remote_addr"] == "192.168.1.100"
        assert entry.parsed_data["status"] == 200

    def test_error_status_codes(self, access_parser):
        """Test handling of different status codes"""
        status_codes = {
            200: "INFO",
            301: "INFO",
            400: "ERROR",
            404: "ERROR",
            500: "ERROR",
        }

        base_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" {status} 521 "-" "-" "-"'

        for status, expected_level in status_codes.items():
            log_line = base_line.format(status=status)
            entry = access_parser.parse_line(log_line)
            assert entry.level == expected_level

    def test_x_forwarded_for_parsing(self, access_parser):
        """Test parsing of X-Forwarded-For header"""
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-" "10.0.0.1, 10.0.0.2"'

        entry = access_parser.parse_line(log_line)

        assert entry.parsed_data["x_forwarded_for"] == ["10.0.0.1", "10.0.0.2"]

    def test_malformed_request(self, access_parser):
        """Test handling of malformed requests"""
        log_lines = [
            # Missing closing quote
            '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1 200 521 "-" "-" "-"',
            # Invalid HTTP method
            '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "INVALID /api HTTP/1.1" 200 521 "-" "-" "-"',
            # Invalid timestamp
            '192.168.1.100 - - [invalid_date] "GET /api HTTP/1.1" 200 521 "-" "-" "-"',
        ]

        for line in log_lines:
            with pytest.raises(ParserError):
                access_parser.parse_line(line)

    def test_empty_fields(self, access_parser):
        """Test handling of empty fields"""
        log_line = (
            '- - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 0 "-" "-" "-"'
        )
        entry = access_parser.parse_line(log_line)

        assert entry.parsed_data["remote_user"] == "-"
        assert entry.parsed_data["body_bytes_sent"] == 0
        assert entry.parsed_data["http_referer"] == "-"


class TestNginxErrorLogParser:
    """Test suite for Nginx error log parser"""

    def test_valid_error_format(self, error_parser):
        """Test parsing of valid error log format"""
        log_line = '2024/02/14 15:48:31 [error] 1234#5678: *123 FastCGI sent in stderr: "PHP message" while reading response header from upstream'

        entry = error_parser.parse_line(log_line)

        assert isinstance(entry.timestamp, datetime)
        assert entry.level == "ERROR"
        assert entry.source == "nginx"
        assert "FastCGI sent in stderr" in entry.message
        assert entry.parsed_data["pid"] == 1234
        assert entry.parsed_data["tid"] == 5678

    def test_error_levels(self, error_parser):
        """Test parsing different error levels"""
        levels = ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"]
        base_line = "2024/02/14 15:48:31 [{level}] 1234#5678: Test message"

        for level in levels:
            log_line = base_line.format(level=level)
            entry = error_parser.parse_line(log_line)
            assert entry.level == level.upper()

    def test_error_with_metadata(self, error_parser):
        """Test error logs with additional metadata"""
        log_line = (
            "2024/02/14 15:48:31 [error] 1234#5678: *123 Test message, "
            "client: 192.168.1.100, "
            "server: example.com, "
            'request: "GET /test HTTP/1.1", '
            'upstream: "upstream-server", '
            'host: "example.com", '
            'referrer: "http://referrer.com"'
        )

        entry = error_parser.parse_line(log_line)

        assert entry.parsed_data["client"] == "192.168.1.100"
        assert entry.parsed_data["server"] == "example.com"
        assert entry.parsed_data["request"] == "GET /test HTTP/1.1"
        assert entry.parsed_data["upstream"] == "upstream-server"
        assert entry.parsed_data["host"] == "example.com"
        assert entry.parsed_data["referrer"] == "http://referrer.com"

    def test_partial_metadata(self, error_parser):
        """Test error logs with partial metadata"""
        log_line = "2024/02/14 15:48:31 [error] 1234#5678: *123 Test message, client: 192.168.1.100"

        entry = error_parser.parse_line(log_line)

        assert entry.parsed_data["client"] == "192.168.1.100"
        assert "server" not in entry.parsed_data
        assert "request" not in entry.parsed_data

    def test_malformed_error_logs(self, error_parser):
        """Test handling of malformed error logs"""
        invalid_lines = [
            # Invalid timestamp
            "invalid_date [error] 1234#5678: Test message",
            # Missing level
            "2024/02/14 15:48:31 1234#5678: Test message",
            # Invalid PID/TID format
            "2024/02/14 15:48:31 [error] invalid_pid: Test message",
        ]

        for line in invalid_lines:
            with pytest.raises(ParserError):
                error_parser.parse_line(line)


@pytest.mark.parametrize("parser_class", [NginxAccessLogParser, NginxErrorLogParser])
def test_parser_thread_safety(parser_class):
    """Test parser thread safety"""
    import queue
    import threading

    parser = parser_class()
    results = queue.Queue()
    errors = queue.Queue()

    def parse_line(line):
        try:
            entry = parser.parse_line(line)
            results.put(entry)
        except Exception as e:
            errors.put(e)

    # Create test data based on parser type
    if parser_class == NginxAccessLogParser:
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-" "-"'
    else:
        log_line = "2024/02/14 15:48:31 [error] 1234#5678: Test message"

    # Create and run multiple threads
    threads = []
    for _ in range(10):
        thread = threading.Thread(target=parse_line, args=(log_line,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Check results
    assert errors.empty()
    assert results.qsize() == 10


def test_parser_performance(benchmark):
    """Test parser performance"""
    parser = NginxAccessLogParser()
    log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-" "-"'

    def parse_line():
        return parser.parse_line(log_line)

    # Run benchmark
    result = benchmark(parse_line)
    assert result is not None
