from datetime import datetime
from typing import Optional
from .base import BaseParser, LogEntry, ParserError
import re

class IncidentLogParser(BaseParser):
    """Parser for incident log format"""
    
    PATTERN = r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[\w:/\s+\-]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    
    def __init__(self):
        self.regex = re.compile(self.PATTERN)
    
    def supports_format(self, line: str) -> bool:
        return bool(self.regex.match(line))
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = self.regex.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        try:
            timestamp = datetime.strptime(
                data['timestamp'],
                '%d/%b/%Y:%H:%M:%S %z'
            )
            
            # Determine level based on status code
            status_code = int(data['status'])
            level = "ERROR" if status_code >= 400 else "INFO"
            
            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=f"{data['request']} - {data['status']}",
                source="incident",
                raw_data=line,
                parsed_data={
                    'ip': data['ip'],
                    'request': data['request'],
                    'status': status_code,
                    'bytes': int(data['bytes']),
                    'referer': data['referer'],
                    'user_agent': data['user_agent']
                },
                metadata={
                    'parser': 'incident'
                }
            )
        except Exception as e:
            raise ParserError(f"Error parsing incident log: {str(e)}") from e