import pytest
from datetime import datetime
from log_analyzer.parsers.apache import ApacheLogParser, ApacheErrorLogParser
from log_analyzer.parsers.base import ParserError

@pytest.fixture
def access_parser():
    return ApacheLogParser()

@pytest.fixture
def error_parser():
    return ApacheErrorLogParser()

class TestApacheAccessLogParser:
    """Test suite for Apache access log parser"""

    def test_valid_combined_format(self, access_parser):
        """Test parsing of valid combined log format"""
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'
        
        entry = access_parser.parse_line(log_line)
        
        assert entry.timestamp == datetime(2024, 2, 10, 13, 55, 36)
        assert entry.level == "INFO"
        assert entry.source == "apache"
        assert entry.parsed_data["ip_address"] == "192.168.1.100"
        assert entry.parsed_data["method"] == "GET"
        assert entry.parsed_data["path"] == "/api/users"
        assert entry.parsed_data["protocol"] == "HTTP/1.1"
        assert entry.parsed_data["status_code"] == 200
        assert entry.parsed_data["bytes_sent"] == 2326
        assert entry.parsed_data["referer"] == "http://example.com"
        assert entry.parsed_data["user_agent"] == "Mozilla/5.0"

    def test_error_status_code(self, access_parser):
        """Test handling of error status codes"""
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /not-found HTTP/1.1" 404 521 "-" "-"'
        
        entry = access_parser.parse_line(log_line)
        
        assert entry.level == "ERROR"
        assert entry.parsed_data["status_code"] == 404

    def test_missing_bytes(self, access_parser):
        """Test handling of missing bytes sent"""
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 - "-" "-"'
        
        entry = access_parser.parse_line(log_line)
        
        assert entry.parsed_data["bytes_sent"] == 0

    def test_malformed_line(self, access_parser):
        """Test handling of malformed log lines"""
        log_line = 'This is not a valid Apache log line'
        
        with pytest.raises(ParserError):
            access_parser.parse_line(log_line)

    def test_supports_format(self, access_parser):
        """Test format detection"""
        valid_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-"'
        invalid_line = 'Invalid log format'
        
        assert access_parser.supports_format(valid_line)
        assert not access_parser.supports_format(invalid_line)

class TestApacheErrorLogParser:
    """Test suite for Apache error log parser"""

    def test_valid_error_format(self, error_parser):
        """Test parsing of valid error log format"""
        log_line = '[Wed Feb 14 15:48:31.999437 2024] [core:error] [pid 1234] [client 192.168.1.100:51234] File does not exist: /var/www/404.html'
        
        entry = error_parser.parse_line(log_line)
        
        assert isinstance(entry.timestamp, datetime)
        assert entry.level == "ERROR"
        assert entry.source == "apache"
        assert "File does not exist" in entry.message
        assert entry.parsed_data["error_message"] == "File does not exist: /var/www/404.html"

    def test_different_error_levels(self, error_parser):
        """Test parsing different error levels"""
        levels = ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"]
        
        for level in levels:
            log_line = f'[Wed Feb 14 15:48:31.999437 2024] [core:{level}] [pid 1234] Test message'
            entry = error_parser.parse_line(log_line)
            assert entry.level == level.upper()

    def test_malformed_error_line(self, error_parser):
        """Test handling of malformed error log lines"""
        log_line = 'This is not a valid Apache error log line'
        
        with pytest.raises(ParserError):
            error_parser.parse_line(log_line)

    def test_supports_error_format(self, error_parser):
        """Test error format detection"""
        valid_line = '[Wed Feb 14 15:48:31.999437 2024] [core:error] [pid 1234] Test message'
        invalid_line = 'Invalid log format'
        
        assert error_parser.supports_format(valid_line)
        assert not error_parser.supports_format(invalid_line)

    def test_error_metadata(self, error_parser):
        """Test error log metadata"""
        log_line = '[Wed Feb 14 15:48:31.999437 2024] [core:error] [pid 1234] Test message'
        
        entry = error_parser.parse_line(log_line)
        
        assert entry.metadata["log_type"] == "error"
        assert entry.metadata["server_type"] == "apache"

@pytest.mark.parametrize("parser_class", [ApacheLogParser, ApacheErrorLogParser])
def test_parser_thread_safety(parser_class):
    """Test parser thread safety"""
    import threading
    
    parser = parser_class()
    results = []
    errors = []
    
    def parse_line(line):
        try:
            entry = parser.parse_line(line)
            results.append(entry)
        except Exception as e:
            errors.append(e)
    
    # Create and run multiple threads
    threads = []
    if parser_class == ApacheLogParser:
        log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-"'
    else:
        log_line = '[Wed Feb 14 15:48:31.999437 2024] [core:error] [pid 1234] Test message'
    
    for _ in range(10):
        thread = threading.Thread(target=parse_line, args=(log_line,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    assert not errors
    assert len(results) == 10

def test_apache_parser_performance(benchmark, access_parser):
    """Test parser performance"""
    log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-"'
    
    def parse_line():
        return access_parser.parse_line(log_line)
    
    result = benchmark(parse_line)
    assert result is not None

def test_memory_usage():
    """Test memory usage with large number of parsings"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    parser = ApacheLogParser()
    log_line = '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 521 "-" "-"'
    
    # Parse multiple lines
    entries = [parser.parse_line(log_line) for _ in range(10000)]
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Check that memory usage increase is reasonable (less than 10MB for 10k entries)
    assert memory_increase < 10 * 1024 * 1024