import pytest
from datetime import datetime
import pytz
import ipaddress
from log_analyzer.parsers.base import LogEntry
from log_analyzer.processors.transformers import (
    LogTransformer,
    TransformerFactory
)

@pytest.fixture
def sample_entry():
    """Create a sample log entry for testing"""
    return LogEntry(
        timestamp=datetime.now(),
        level="INFO",
        message="Test message with password=secret123",
        source="test",
        raw_data="raw log line",
        parsed_data={
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        },
        metadata={}
    )

class TestLogTransformer:
    """Test LogTransformer functionality"""
    
    def test_normalize_timestamp(self):
        """Test timestamp normalization"""
        # Create entry with non-UTC timestamp
        local_tz = pytz.timezone('America/New_York')
        local_time = local_tz.localize(datetime.now())
        
        entry = LogEntry(
            timestamp=local_time,
            level="INFO",
            message="Test",
            source="test",
            raw_data="raw",
            parsed_data={},
            metadata={}
        )
        
        result = LogTransformer.normalize_timestamp(entry)
        assert result.timestamp.tzinfo == pytz.UTC
    
    def test_normalize_level(self):
        """Test log level normalization"""
        level_mappings = {
            "EMERGENCY": "CRITICAL",
            "ALERT": "CRITICAL",
            "ERR": "ERROR",
            "WARN": "WARNING",
            "NOTICE": "INFO",
            "FINE": "DEBUG",
            "TRACE": "DEBUG"
        }
        
        for input_level, expected_level in level_mappings.items():
            entry = LogEntry(
                timestamp=datetime.now(),
                level=input_level,
                message="Test",
                source="test",
                raw_data="raw",
                parsed_data={},
                metadata={}
            )
            
            result = LogTransformer.normalize_level(entry)
            assert result.level == expected_level
    
    def test_mask_sensitive_data(self, sample_entry):
        """Test sensitive data masking"""
        patterns = {
            "password": r'password["\s]*[:=]\s*["\']?\w+["\']?',
            "api_key": r'api[_-]key["\s]*[:=]\s*["\']?\w+["\']?',
            "token": r'token["\s]*[:=]\s*["\']?\w+["\']?'
        }
        
        # Add sensitive data to parsed_data
        sample_entry.parsed_data.update({
            "password": "secret123",
            "api_key": "abcd1234",
            "token": "xyz789"
        })
        
        result = LogTransformer.mask_sensitive_data(sample_entry, patterns)
        
        # Check message masking
        assert "password=secret123" not in result.message
        assert "***MASKED***" in result.message
        
        # Check parsed data masking
        assert result.parsed_data["password"] == "***MASKED***"
        assert result.parsed_data["api_key"] == "***MASKED***"
        assert result.parsed_data["token"] == "***MASKED***"
    
    def test_enrich_ip_data(self, sample_entry):
        """Test IP data enrichment"""
        result = LogTransformer.enrich_ip_data(sample_entry)
        
        assert result.parsed_data["ip_version"] == 4
        assert result.parsed_data["ip_type"] == "private"
        
        # Test public IP
        sample_entry.parsed_data["ip"] = "8.8.8.8"
        result = LogTransformer.enrich_ip_data(sample_entry)
        assert result.parsed_data["ip_type"] == "public"
        
        # Test IPv6
        sample_entry.parsed_data["ip"] = "2001:db8::1"
        result = LogTransformer.enrich_ip_data(sample_entry)
        assert result.parsed_data["ip_version"] == 6
    
    def test_parse_user_agent(self, sample_entry):
        """Test user agent parsing"""
        result = LogTransformer.parse_user_agent(sample_entry)
        ua_data = result.parsed_data["user_agent_parsed"]
        
        assert ua_data["browser"] == "Chrome"
        assert ua_data["browser_version"] == "91.0.4472.124"
        assert ua_data["os"] == "Windows"
        assert ua_data["os_version"] == "10.0"
        assert not ua_data["is_mobile"]
        
        # Test mobile user agent
        sample_entry.parsed_data["user_agent"] = (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 "
            "Mobile/15E148 Safari/604.1"
        )
        result = LogTransformer.parse_user_agent(sample_entry)
        ua_data = result.parsed_data["user_agent_parsed"]
        
        assert ua_data["browser"] == "Safari"
        assert ua_data["os"] == "iOS"
        assert ua_data["is_mobile"]

class TestTransformerFactory:
    """Test TransformerFactory functionality"""
    
    def test_standard_transformer(self, sample_entry):
        """Test standard transformer pipeline"""
        transformer = TransformerFactory.create_standard_transformer()
        result = transformer(sample_entry)
        
        assert result.timestamp.tzinfo == pytz.UTC
        assert "ip_version" in result.parsed_data
        assert "ip_type" in result.parsed_data
    
    def test_security_transformer(self, sample_entry):
        """Test security transformer pipeline"""
        transformer = TransformerFactory.create_security_transformer()
        
        # Add sensitive data
        sample_entry.message = "API key=1234567890"
        sample_entry.parsed_data["api_key"] = "1234567890"
        
        result = transformer(sample_entry)
        
        assert "1234567890" not in result.message
        assert result.parsed_data["api_key"] == "***MASKED***"
        assert "ip_version" in result.parsed_data
        assert "ip_type" in result.parsed_data

    def test_web_access_transformer(self, sample_entry):
        """Test web access transformer pipeline"""
        transformer = TransformerFactory.create_web_access_transformer()
        result = transformer(sample_entry)

        assert result.timestamp.tzinfo == pytz.UTC
        assert "ip_version" in result.parsed_data
        assert "ip_type" in result.parsed_data
        assert "user_agent_parsed" in result.parsed_data

    def test_custom_mask_patterns(self, sample_entry):
        """Test security transformer with custom mask patterns"""
        custom_patterns = {
            "ssn": r'\d{3}-\d{2}-\d{4}',
            "credit_card": r'\d{4}-\d{4}-\d{4}-\d{4}'
        }

        transformer = TransformerFactory.create_security_transformer(
            mask_patterns=custom_patterns
        )

        sample_entry.message = "SSN: 123-45-6789, CC: 1234-5678-9012-3456"
        result = transformer(sample_entry)

        assert "123-45-6789" not in result.message
        assert "1234-5678-9012-3456" not in result.message
        assert "***MASKED***" in result.message

class TestTransformerChaining:
    """Test transformer chaining functionality"""

    def test_multiple_transformations(self, sample_entry):
        """Test applying multiple transformations"""
        def transform_chain(entry: LogEntry) -> LogEntry:
            return (entry
                .pipe(LogTransformer.normalize_timestamp)
                .pipe(LogTransformer.normalize_level)
                .pipe(LogTransformer.enrich_ip_data)
                .pipe(LogTransformer.parse_user_agent))

        result = transform_chain(sample_entry)

        assert result.timestamp.tzinfo == pytz.UTC
        assert "ip_version" in result.parsed_data
        assert "user_agent_parsed" in result.parsed_data

    def test_conditional_transformation(self, sample_entry):
        """Test conditional transformation application"""
        def conditional_transform(entry: LogEntry) -> LogEntry:
            if entry.level == "ERROR":
                return entry.pipe(LogTransformer.mask_sensitive_data({
                    "error": r'error["\s]*[:=]\s*["\']?\w+["\']?'
                }))
            return entry

        # Test with INFO level
        result = conditional_transform(sample_entry)
        assert result is sample_entry

        # Test with ERROR level
        sample_entry.level = "ERROR"
        sample_entry.message = "error=critical_failure"
        result = conditional_transform(sample_entry)
        assert "critical_failure" not in result.message

class TestTransformerPerformance:
    """Test transformer performance characteristics"""

    def test_large_scale_transformation(self, benchmark):
        """Test performance with large number of transformations"""
        entries = []
        for i in range(1000):
            entry = LogEntry(
                timestamp=datetime.now(),
                level="INFO",
                message=f"Test message {i}",
                source="test",
                raw_data=f"raw line {i}",
                parsed_data={
                    "ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },
                metadata={}
            )
            entries.append(entry)

        transformer = TransformerFactory.create_standard_transformer()

        def transform_batch():
            return [transformer(entry) for entry in entries]

        results = benchmark(transform_batch)
        assert len(results) == 1000

    def test_memory_usage(self):
        """Test memory usage during transformations"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Perform memory-intensive operations
        entries = []
        transformer = TransformerFactory.create_standard_transformer()

        for i in range(10000):
            entry = LogEntry(
                timestamp=datetime.now(),
                level="INFO",
                message=f"Test message {i} with some longer content...",
                source="test",
                raw_data="raw data",
                parsed_data={
                    "ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "extra_data": "some additional data..."
                },
                metadata={}
            )
            result = transformer(entry)
            entries.append(result)

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Check that memory usage increase is reasonable (less than 50MB for 10k entries)
        assert memory_increase < 50 * 1024 * 1024

    def test_transformer_error_handling(self):
        """Test error handling in transformers"""
        def failing_enrichment(entry: LogEntry) -> LogEntry:
            raise ValueError("Enrichment failed")

        entry = LogEntry(
            timestamp=datetime.now(),
            level="INFO",
            message="Test message",
            source="test",
            raw_data="raw data",
            parsed_data={},
            metadata={}
        )

        with pytest.raises(ValueError) as exc_info:
            entry.pipe(failing_enrichment)
        assert str(exc_info.value) == "Enrichment failed"

if __name__ == '__main__':
    pytest.main([__file__])