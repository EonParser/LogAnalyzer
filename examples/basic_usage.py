import json
from datetime import datetime, timedelta
from pathlib import Path

from log_analyzer.core.analyzer import LogAnalyzer
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.base import ParserFactory
from log_analyzer.parsers.nginx import NginxAccessLogParser
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.processors.pipeline import FilterStep, Pipeline, TransformStep
from log_analyzer.processors.transformers import LogTransformer, TransformerFactory


def main():
    """Main function demonstrating different usage scenarios"""
    # Initialize core components
    analyzer = LogAnalyzer()
    parser_factory = ParserFactory()

    # Register parsers
    parser_factory.register_parser("apache", ApacheLogParser)
    parser_factory.register_parser("nginx", NginxAccessLogParser)
    parser_factory.register_parser("syslog", SyslogParser)

    # Example 1: Simple log analysis
    print("\nExample 1: Simple Log Analysis")
    print("-" * 50)
    simple_analysis(analyzer)

    # Example 2: Analysis with filtering and transformation
    print("\nExample 2: Analysis with Pipeline Processing")
    print("-" * 50)
    advanced_analysis(analyzer)

    # Example 3: Real-time monitoring
    print("\nExample 3: Real-time Log Monitoring")
    print("-" * 50)
    monitor_logs(analyzer)


def simple_analysis(analyzer: LogAnalyzer):
    """Demonstrate simple log analysis"""
    # Create sample log data
    sample_log = """
192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326
192.168.1.101 - - [10/Feb/2024:13:55:37 +0000] "POST /api/login HTTP/1.1" 401 1234
192.168.1.102 - - [10/Feb/2024:13:55:38 +0000] "GET /api/products HTTP/1.1" 500 892
    """.strip()

    # Write sample data to temporary file
    log_file = Path("temp_access.log")
    log_file.write_text(sample_log)

    try:
        # Analyze the log file
        results = analyzer.analyze_file(log_file, parser_name="apache")

        # Print results
        print_analysis_results(results)

    finally:
        # Cleanup
        log_file.unlink()


def advanced_analysis(analyzer: LogAnalyzer):
    """Demonstrate advanced analysis with pipeline processing"""
    # Create processing pipeline
    pipeline = Pipeline()

    # Add filtering for errors
    pipeline.add_step(
        FilterStep(
            "error_filter",
            lambda entry: entry.level in {"ERROR", "CRITICAL", "WARNING"},
        )
    )

    # Add custom transformation
    pipeline.add_step(TransformStep("enrich_errors", LogTransformer.enrich_ip_data))

    # Create sample error logs
    sample_logs = """
<13>Feb 10 13:55:36 myapp[12345]: Critical database connection error
<14>Feb 10 13:55:37 myapp[12345]: Warning: High memory usage detected
<11>Feb 10 13:55:38 myapp[12345]: Emergency: System shutdown initiated
    """.strip()

    # Write sample data
    log_file = Path("temp_syslog.log")
    log_file.write_text(sample_logs)

    try:
        # Analyze with pipeline
        results = analyzer.analyze_file(
            log_file, parser_name="syslog", pipeline=pipeline
        )

        # Print results
        print_analysis_results(results)

    finally:
        # Cleanup
        log_file.unlink()


def monitor_logs(analyzer: LogAnalyzer):
    """Demonstrate real-time log monitoring"""
    # Create a monitoring pipeline
    pipeline = Pipeline()

    # Add alert trigger for critical events
    def alert_on_critical(entry):
        if entry.level == "CRITICAL":
            print(f"ALERT: Critical event detected - {entry.message}")
        return entry

    pipeline.add_step(TransformStep("alert_trigger", alert_on_critical))

    # Simulate real-time logs
    sample_logs = [
        '192.168.1.100 - - [10/Feb/2024:13:55:36 +0000] "GET /api/status HTTP/1.1" 200 1234',
        '192.168.1.101 - - [10/Feb/2024:13:55:37 +0000] "GET /api/health HTTP/1.1" 503 892',
        '192.168.1.102 - - [10/Feb/2024:13:55:38 +0000] "POST /api/data HTTP/1.1" 500 567',
    ]

    log_file = Path("temp_monitor.log")

    try:
        # Simulate log updates
        for log_line in sample_logs:
            # Write new log line
            with log_file.open("a") as f:
                f.write(log_line + "\n")

            # Analyze latest logs
            results = analyzer.analyze_file(
                log_file, parser_name="apache", pipeline=pipeline
            )

            # Print latest metrics
            print("\nLatest Metrics:")
            print(f"Total Entries: {results.get('total_entries', 0)}")
            print(f"Error Rate: {results.get('error_rate', 0):.2%}")

    finally:
        # Cleanup
        log_file.unlink()


def print_analysis_results(results: dict):
    """Print analysis results in a readable format"""
    print("\nAnalysis Results:")
    print("-" * 30)

    for key, value in results.items():
        if key == "errors":
            print(f"\nErrors ({value['count']} total):")
            for error in value["messages"][-5:]:  # Show last 5 errors
                print(f"  - {error}")
        elif key == "level_distribution":
            print("\nLog Level Distribution:")
            for level, count in value.items():
                print(f"  {level}: {count}")
        elif key == "time_range":
            print("\nTime Range:")
            print(f"  Start: {value['start']}")
            print(f"  End: {value['end']}")
            print(f"  Duration: {value['duration_seconds']/3600:.2f} hours")
        elif isinstance(value, (int, float, str)):
            print(f"\n{key.replace('_', ' ').title()}: {value}")


if __name__ == "__main__":
    main()
