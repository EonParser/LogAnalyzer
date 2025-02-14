from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import re

from log_analyzer.core.analyzer import LogAnalyzer
from log_analyzer.parsers.base import BaseParser, LogEntry, ParserError
from log_analyzer.processors.pipeline import Pipeline, TransformStep
from log_analyzer.processors.transformers import LogTransformer

class CustomAppLogParser(BaseParser):
    """Example custom parser for application-specific log format
    
    Example log format:
    [2024-02-10 13:55:36] [INFO] [UserService] User login successful - user_id=123 ip=192.168.1.100
    [2024-02-10 13:55:37] [ERROR] [AuthService] Authentication failed - attempts=3 ip=192.168.1.101
    """
    
    PATTERN = (
        r'\[(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'\[(?P<service>\w+)\]\s+'
        r'(?P<message>.*?)(?:\s+-\s+(?P<metadata>.*))?$'
    )
    
    def __init__(self):
        self.regex = re.compile(self.PATTERN)
        
    def supports_format(self, line: str) -> bool:
        """Check if line matches our custom format"""
        return bool(self.regex.match(line))
        
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a log line in our custom format"""
        match = self.regex.match(line)
        if not match:
            raise ParserError(f"Line does not match custom format: {line}")
            
        data = match.groupdict()
        
        try:
            # Parse timestamp
            timestamp = datetime.strptime(
                data['timestamp'],
                '%Y-%m-%d %H:%M:%S'
            )
            
            # Parse metadata key-value pairs
            metadata = {}
            if data['metadata']:
                for pair in data['metadata'].split():
                    try:
                        key, value = pair.split('=', 1)
                        metadata[key] = value
                    except ValueError:
                        continue
            
            return LogEntry(
                timestamp=timestamp,
                level=data['level'].upper(),
                message=data['message'],
                source=data['service'],
                raw_data=line,
                parsed_data=metadata,
                metadata={
                    'log_type': 'application',
                    'service': data['service']
                }
            )
            
        except (ValueError, KeyError) as e:
            raise ParserError(f"Error parsing custom log: {str(e)}") from e

def main():
    """Demonstrate custom parser usage"""
    # Create sample logs
    sample_logs = """
[2024-02-10 13:55:36] [INFO] [UserService] User login successful - user_id=123 ip=192.168.1.100
[2024-02-10 13:55:37] [ERROR] [AuthService] Authentication failed - attempts=3 ip=192.168.1.101
[2024-02-10 13:55:38] [WARN] [UserService] Rate limit reached - user_id=123 limit=100
[2024-02-10 13:55:39] [ERROR] [DatabaseService] Connection failed - retries=3 host=db1
    """.strip()
    
    # Write sample logs to file
    log_file = Path('temp_custom.log')
    log_file.write_text(sample_logs)
    
    try:
        # Initialize analyzer with custom parser
        analyzer = LogAnalyzer()
        analyzer.parser_factory.register_parser('custom', CustomAppLogParser)
        
        # Create processing pipeline
        pipeline = Pipeline()
        
        # Add custom enrichment
        def enrich_service_info(entry: LogEntry) -> LogEntry:
            """Add service-specific information"""
            if entry.source == 'UserService':
                entry.metadata['service_type'] = 'user_management'
                entry.metadata['criticality'] = 'high'
            elif entry.source == 'AuthService':
                entry.metadata['service_type'] = 'security'
                entry.metadata['criticality'] = 'critical'
            elif entry.source == 'DatabaseService':
                entry.metadata['service_type'] = 'infrastructure'
                entry.metadata['criticality'] = 'critical'
            return entry
        
        pipeline.add_step(
            TransformStep('service_enrichment', enrich_service_info)
        )
        
        # Add IP information enrichment for relevant logs
        pipeline.add_step(
            TransformStep('ip_enrichment', LogTransformer.enrich_ip_data)
        )
        
        # Analyze logs
        results = analyzer.analyze_file(
            log_file,
            parser_name='custom',
            pipeline=pipeline
        )
        
        # Print results
        print("\nCustom Log Analysis Results:")
        print("-" * 40)
        
        # Print general statistics
        print(f"\nTotal Entries: {results['total_entries']}")
        print(f"Error Count: {results['errors']['count']}")
        
        # Print level distribution
        print("\nLog Level Distribution:")
        for level, count in results['level_distribution'].items():
            print(f"  {level}: {count}")
        
        # Print service distribution
        print("\nService Distribution:")
        services = {}
        for entry in results['entries']:
            service = entry.source
            services[service] = services.get(service, 0) + 1
        for service, count in services.items():
            print(f"  {service}: {count}")
        
        # Print sample enriched data
        print("\nSample Enriched Entries:")
        for entry in results['entries'][:2]:
            print(f"\n  Timestamp: {entry.timestamp}")
            print(f"  Level: {entry.level}")
            print(f"  Service: {entry.source}")
            print(f"  Message: {entry.message}")
            print("  Metadata:")
            for key, value in entry.metadata.items():
                print(f"    {key}: {value}")
        
    finally:
        # Cleanup
        log_file.unlink()

if __name__ == '__main__':
    main()