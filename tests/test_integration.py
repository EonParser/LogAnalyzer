import gzip
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer.core.analyzer import LogAnalyzer
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.base import ParserFactory
from log_analyzer.parsers.nginx import NginxAccessLogParser
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.processors.pipeline import FilterStep, Pipeline, TransformStep
from log_analyzer.processors.transformers import LogTransformer, TransformerFactory


@pytest.fixture
def analyzer():
    """Create fully configured analyzer instance"""
    parser_factory = ParserFactory()
    parser_factory.register_parser("apache", ApacheLogParser)
    parser_factory.register_parser("nginx", NginxAccessLogParser)
    parser_factory.register_parser("syslog", SyslogParser)
    return LogAnalyzer(parser_factory=parser_factory)


@pytest.fixture
def sample_logs(tmp_path):
    """Create sample log files of different types"""
    # Apache access logs
    apache_logs = tmp_path / "apache_access.log"
    apache_content = [
        '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"',
        '192.168.1.101 - - [10/Feb/2024:13:55:37 +0000] "POST /api/login HTTP/1.1" 401 1234 "-" "curl/7.64.1"',
        '192.168.1.102 - - [10/Feb/2024:13:55:38 +0000] "GET /api/admin HTTP/1.1" 403 892 "-" "PostmanRuntime/7.29.2"',
    ]
    apache_logs.write_text("\n".join(apache_logs))

    # Nginx access logs
    nginx_logs = tmp_path / "nginx_access.log"
    nginx_content = [
        '192.168.1.100 - john [10/Feb/2024:13:55:36 +0000] "GET /app/status HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0" "-"',
        '192.168.1.101 - jane [10/Feb/2024:13:55:37 +0000] "POST /app/data HTTP/1.1" 500 1234 "-" "curl/7.64.1" "-"',
    ]
    nginx_logs.write_text("\n".join(nginx_content))

    # Syslog format
    syslog_logs = tmp_path / "syslog"
    syslog_content = [
        "<13>Feb 10 13:55:36 myapp[12345]: Connection established",
        "<14>Feb 10 13:55:37 myapp[12345]: User authentication successful",
        "<11>Feb 10 13:55:38 myapp[12345]: Critical system error detected",
    ]
    syslog_logs.write_text("\n".join(syslog_content))

    # Compressed logs
    with gzip.open(tmp_path / "apache_access.log.gz", "wt") as f:
        f.write("\n".join(apache_content))

    return tmp_path


def test_multi_format_analysis(analyzer, sample_logs):
    """Test analyzing multiple log formats"""
    results = analyzer.analyze_directory(sample_logs, pattern="*.log")

    assert results["total_entries"] > 0
    assert "apache" in results["sources"]
    assert "nginx" in results["sources"]


def test_compressed_file_handling(analyzer, sample_logs):
    """Test handling of compressed log files"""
    results = analyzer.analyze_file(
        sample_logs / "apache_access.log.gz", parser_name="apache"
    )

    assert results["total_entries"] == 3
    assert results["errors"]["count"] == 0


def test_error_detection_pipeline(analyzer, sample_logs):
    """Test pipeline for error detection"""
    pipeline = Pipeline()

    # Add error detection steps
    pipeline.add_step(
        FilterStep(
            "error_filter",
            lambda e: e.level in {"ERROR", "CRITICAL"}
            or e.parsed_data.get("status", 200) >= 400,
        )
    )

    # Add enrichment
    transformer = TransformerFactory.create_standard_transformer()
    pipeline.add_step(TransformStep("enrich", transformer))

    results = analyzer.analyze_directory(
        sample_logs, pattern="*.log", pipeline=pipeline
    )

    # Verify error detection
    assert results["total_entries"] > 0
    assert all(
        entry.level in {"ERROR", "CRITICAL"}
        or entry.parsed_data.get("status", 200) >= 400
        for entry in results["entries"]
    )


def test_security_analysis_pipeline(analyzer, sample_logs):
    """Test security-focused analysis pipeline"""
    pipeline = Pipeline()

    # Add security-focused steps
    transformer = TransformerFactory.create_security_transformer(
        {
            "password": r'password["\s]*[:=]\s*["\']?\w+["\']?',
            "token": r'token["\s]*[:=]\s*["\']?\w+["\']?',
            "api_key": r'api[_-]key["\s]*[:=]\s*["\']?\w+["\']?',
        }
    )

    pipeline.add_step(TransformStep("security_transform", transformer))

    # Add IP-based filtering
    pipeline.add_step(
        FilterStep(
            "suspicious_ips",
            lambda e: (
                e.parsed_data.get("status", 200) >= 400
                or e.level in {"ERROR", "CRITICAL"}
            ),
        )
    )

    results = analyzer.analyze_directory(
        sample_logs, pattern="*.log", pipeline=pipeline
    )

    # Verify security analysis
    for entry in results["entries"]:
        # Check sensitive data masking
        assert "password=" not in entry.message
        assert "token=" not in entry.message
        assert "api_key=" not in entry.message

        # Check IP enrichment
        if "ip" in entry.parsed_data:
            assert "ip_version" in entry.parsed_data
            assert "ip_type" in entry.parsed_data


def test_performance_monitoring(analyzer, sample_logs):
    """Test performance monitoring capabilities"""
    start_time = datetime.now()

    # Process logs multiple times to simulate load
    for _ in range(5):
        results = analyzer.analyze_directory(sample_logs, pattern="*.log")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Basic performance metrics
    total_entries = results["total_entries"]
    entries_per_second = total_entries / duration

    # Performance assertions
    assert entries_per_second > 100  # Minimum performance threshold
    assert results["errors"]["count"] == 0  # No errors during processing


def test_concurrent_processing(analyzer, sample_logs):
    """Test concurrent processing of multiple files"""
    # Create multiple large log files
    for i in range(5):
        log_file = sample_logs / f"large_file_{i}.log"
        with open(log_file, "w") as f:
            for j in range(1000):
                f.write(
                    f'192.168.1.100 - - [10/Feb/2024:13:55:{j:02d} +0000] "GET /api/test HTTP/1.1" 200 100 "-" "-"\n'
                )

    results = analyzer.analyze_directory(
        sample_logs, pattern="large_file_*.log", max_workers=3
    )

    assert results["total_entries"] == 5000
    assert results["errors"]["count"] == 0


if __name__ == "__main__":
    pytest.main([__file__])
