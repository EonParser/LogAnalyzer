import re
from datetime import datetime
from typing import Optional, Dict, Any
from .base import BaseParser, LogEntry, ParserError

class SyslogParser(BaseParser):
    """Parser for standard syslog format (RFC 3164 and 5424)"""
    
    # RFC 3164 pattern (old BSD format)
    BSD_PATTERN = (
        r'(?P<priority><\d+>)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\-]+)\s+'
        r'(?P<program>[\w\-\(\)]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )
    
    # RFC 5424 pattern (new format)
    RFC5424_PATTERN = (
        r'(?P<priority><\d+>)'
        r'(?P<version>\d+)\s+'
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+'
        r'(?P<hostname>[\w\-]+)\s+'
        r'(?P<program>[\w\-\(\)]+)\s+'
        r'(?P<pid>[-\w\.]+)\s+'
        r'(?P<msgid>[-\w\.]+)\s+'
        r'(?P<structured_data>(?:\[.*?\])*)\s*'
        r'(?P<message>.*)'
    )
    
    # Priority mapping according to RFC 5424
    FACILITY_MAP = {
        0: 'kern',
        1: 'user',
        2: 'mail',
        3: 'daemon',
        4: 'auth',
        5: 'syslog',
        6: 'lpr',
        7: 'news',
        8: 'uucp',
        9: 'cron',
        10: 'authpriv',
        11: 'ftp',
        12: 'ntp',
        13: 'security',
        14: 'console',
        15: 'cron2',
        16: 'local0',
        17: 'local1',
        18: 'local2',
        19: 'local3',
        20: 'local4',
        21: 'local5',
        22: 'local6',
        23: 'local7'
    }
    
    SEVERITY_MAP = {
        0: 'EMERGENCY',
        1: 'ALERT',
        2: 'CRITICAL',
        3: 'ERROR',
        4: 'WARNING',
        5: 'NOTICE',
        6: 'INFO',
        7: 'DEBUG'
    }
    
    def __init__(self):
        """Initialize parser with both RFC 3164 and 5424 patterns"""
        self.bsd_regex = re.compile(self.BSD_PATTERN)
        self.rfc5424_regex = re.compile(self.RFC5424_PATTERN)
        
    def supports_format(self, line: str) -> bool:
        """Check if line matches either syslog format"""
        return bool(self.bsd_regex.match(line) or self.rfc5424_regex.match(line))
        
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a syslog line into structured data
        
        Args:
            line: Raw log line to parse
            
        Returns:
            LogEntry if successful, None if line should be skipped
            
        Raises:
            ParserError: If line cannot be parsed
        """
        # Try RFC 5424 format first
        match = self.rfc5424_regex.match(line)
        if match:
            return self._parse_rfc5424(match, line)
            
        # Try BSD format
        match = self.bsd_regex.match(line)
        if match:
            return self._parse_bsd(match, line)
            
        raise ParserError(f"Line does not match any syslog format: {line}")
        
    def _parse_priority(self, priority_str: Optional[str]) -> tuple[str, str]:
        """Parse priority value into facility and severity
        
        Args:
            priority_str: Priority string like '<13>'
            
        Returns:
            Tuple of (facility, severity)
        """
        if not priority_str:
            return 'user', 'INFO'
            
        try:
            priority = int(priority_str.strip('<>'))
            facility_num = priority >> 3
            severity_num = priority & 0x07
            
            facility = self.FACILITY_MAP.get(facility_num, 'user')
            severity = self.SEVERITY_MAP.get(severity_num, 'INFO')
            
            return facility, severity
        except (ValueError, KeyError):
            return 'user', 'INFO'
            
    def _parse_rfc5424(self, match: re.Match, line: str) -> LogEntry:
        """Parse RFC 5424 format match"""
        data = match.groupdict()
        
        try:
            # Parse timestamp
            timestamp = datetime.fromisoformat(
                data['timestamp'].replace('Z', '+00:00')
            )
            
            # Parse priority
            facility, severity = self._parse_priority(data['priority'])
            
            # Parse structured data
            structured_data = {}
            if data['structured_data'] and data['structured_data'] != '-':
                for block in re.finditer(
                    r'\[([^\]]+)\]',
                    data['structured_data']
                ):
                    elements = block.group(1).split(' ')
                    if elements:
                        sd_id = elements[0]
                        params = {}
                        for element in elements[1:]:
                            try:
                                key, value = element.split('=', 1)
                                params[key] = value.strip('"')
                            except ValueError:
                                continue
                        structured_data[sd_id] = params
            
            parsed_data = {
                'facility': facility,
                'severity': severity,
                'version': int(data['version']),
                'hostname': data['hostname'],
                'program': data['program'],
                'pid': data['pid'],
                'msgid': data['msgid'],
                'structured_data': structured_data
            }
            
            return LogEntry(
                timestamp=timestamp,
                level=severity,
                message=data['message'],
                source=data['program'],
                raw_data=line,
                parsed_data=parsed_data,
                metadata={
                    'log_type': 'syslog',
                    'format': 'rfc5424'
                }
            )
            
        except (ValueError, KeyError) as e:
            raise ParserError(
                f"Error parsing RFC 5424 syslog: {str(e)}"
            ) from e
            
    def _parse_bsd(self, match: re.Match, line: str) -> LogEntry:
        """Parse BSD format match"""
        data = match.groupdict()
        
        try:
            # Parse timestamp (assume current year)
            current_year = datetime.now().year
            timestamp = datetime.strptime(
                f"{data['timestamp']} {current_year}",
                '%b %d %H:%M:%S %Y'
            )
            
            # Parse priority
            facility, severity = self._parse_priority(data['priority'])
            
            parsed_data = {
                'facility': facility,
                'severity': severity,
                'hostname': data['hostname'],
                'program': data['program'],
                'pid': data['pid'] if data['pid'] else None
            }
            
            return LogEntry(
                timestamp=timestamp,
                level=severity,
                message=data['message'],
                source=data['program'],
                raw_data=line,
                parsed_data=parsed_data,
                metadata={
                    'log_type': 'syslog',
                    'format': 'bsd'
                }
            )
            
        except (ValueError, KeyError) as e:
            raise ParserError(
                f"Error parsing BSD syslog: {str(e)}"
            ) from e

class SystemdJournalParser(BaseParser):
    """Parser for systemd journal logs"""
    
    def supports_format(self, line: str) -> bool:
        """Check if line is JSON and has systemd-specific fields"""
        try:
            import json
            data = json.loads(line)
            return all(field in data for field in 
                      ['__REALTIME_TIMESTAMP', 'MESSAGE', 'PRIORITY'])
        except (json.JSONDecodeError, TypeError):
            return False
            
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a systemd journal log entry"""
        try:
            import json
            data = json.loads(line)
            
            # Parse timestamp (microseconds since epoch)
            timestamp = datetime.fromtimestamp(
                int(data['__REALTIME_TIMESTAMP']) / 1000000
            )
            
            # Map priority to severity
            severity = SyslogParser.SEVERITY_MAP.get(
                int(data['PRIORITY']),
                'INFO'
            )
            
            parsed_data = {
                'unit': data.get('_SYSTEMD_UNIT', 'unknown'),
                'machine_id': data.get('_MACHINE_ID'),
                'boot_id': data.get('_BOOT_ID'),
                'pid': data.get('_PID'),
                'uid': data.get('_UID'),
                'gid': data.get('_GID'),
                'command': data.get('_COMM'),
                'executable': data.get('_EXE'),
                'systemd_slice': data.get('_SYSTEMD_SLICE'),
                'transport': data.get('_TRANSPORT')
            }
            
            # Remove None values
            parsed_data = {
                k: v for k, v in parsed_data.items() if v is not None
            }
            
            return LogEntry(
                timestamp=timestamp,
                level=severity,
                message=data['MESSAGE'],
                source=parsed_data.get('unit', 'systemd'),
                raw_data=line,
                parsed_data=parsed_data,
                metadata={
                    'log_type': 'journal',
                    'format': 'systemd'
                }
            )
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ParserError(
                f"Error parsing systemd journal: {str(e)}"
            ) from e