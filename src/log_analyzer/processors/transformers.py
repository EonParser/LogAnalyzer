from typing import Callable, Dict, Any, Optional
from datetime import datetime, timezone
import re
import ipaddress
from ..parsers.base import LogEntry

class LogTransformer:
    """Collection of common log transformation functions"""
    
    @staticmethod
    def normalize_timestamp(entry: LogEntry) -> LogEntry:
        """Convert timestamp to UTC and ISO format"""
        if entry.timestamp.tzinfo is None:
            # Assume UTC for naive timestamps
            entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)
        else:
            # Convert to UTC
            entry.timestamp = entry.timestamp.astimezone(timezone.utc)
        return entry
    
    @staticmethod
    def normalize_level(entry: LogEntry) -> LogEntry:
        """Normalize log levels to standard format"""
        level_mapping = {
            'EMERGENCY': 'CRITICAL',
            'ALERT': 'CRITICAL',
            'CRIT': 'CRITICAL',
            'ERR': 'ERROR',
            'WARN': 'WARNING',
            'NOTICE': 'INFO',
            'DEBUG2': 'DEBUG',
            'DEBUG3': 'DEBUG',
            'FINE': 'DEBUG',
            'FINER': 'DEBUG',
            'FINEST': 'DEBUG',
            'TRACE': 'DEBUG'
        }
        entry.level = level_mapping.get(entry.level.upper(), entry.level.upper())
        return entry

    @staticmethod
    def mask_sensitive_data(entry: LogEntry, 
                          patterns: Dict[str, str]) -> LogEntry:
        """Mask sensitive data in log messages and parsed data
        
        Args:
            entry: Log entry to process
            patterns: Dictionary of field names and regex patterns to mask
        """
        for field, pattern in patterns.items():
            # Mask in message
            entry.message = re.sub(
                pattern,
                '***MASKED***',
                entry.message
            )
            
            # Mask in parsed data
            if field in entry.parsed_data:
                entry.parsed_data[field] = '***MASKED***'
                
        return entry
    
    @staticmethod
    def enrich_ip_data(entry: LogEntry) -> LogEntry:
        """Enrich log entry with IP address information"""
        ip_fields = ['ip', 'ip_address', 'source_ip', 'client_ip']
        
        for field in ip_fields:
            ip_str = entry.parsed_data.get(field)
            if ip_str:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    entry.parsed_data[f'{field}_version'] = ip.version
                    entry.parsed_data[f'{field}_type'] = (
                        'private' if ip.is_private else 'public'
                    )
                except ValueError:
                    continue
                    
        return entry
    
    @staticmethod
    def parse_user_agent(entry: LogEntry) -> LogEntry:
        """Parse user agent string into components"""
        ua_fields = ['user_agent', 'ua', 'agent']
        
        for field in ua_fields:
            ua_string = entry.parsed_data.get(field)
            if ua_string:
                # Simple user agent parsing
                browser_patterns = [
                    (r'Chrome/(\S+)', 'Chrome'),
                    (r'Firefox/(\S+)', 'Firefox'),
                    (r'Safari/(\S+)', 'Safari'),
                    (r'MSIE (\S+)', 'Internet Explorer'),
                    (r'Edg/(\S+)', 'Edge'),
                ]
                
                os_patterns = [
                    (r'Windows NT (\S+)', 'Windows'),
                    (r'Macintosh', 'MacOS'),
                    (r'Linux', 'Linux'),
                    (r'Android', 'Android'),
                    (r'iOS', 'iOS'),
                ]
                
                ua_data = {
                    'browser': 'Unknown',
                    'browser_version': None,
                    'os': 'Unknown',
                    'os_version': None,
                    'is_mobile': bool(re.search(
                        r'Mobile|Android|iOS|iPhone|iPad', 
                        ua_string
                    ))
                }
                
                # Detect browser
                for pattern, browser in browser_patterns:
                    match = re.search(pattern, ua_string)
                    if match:
                        ua_data['browser'] = browser
                        ua_data['browser_version'] = match.group(1)
                        break
                        
                # Detect OS
                for pattern, os_name in os_patterns:
                    match = re.search(pattern, ua_string)
                    if match:
                        ua_data['os'] = os_name
                        if match.groups():
                            ua_data['os_version'] = match.group(1)
                        break
                        
                entry.parsed_data[f'{field}_parsed'] = ua_data
                
        return entry

class TransformerFactory:
    """Factory for creating common transformer combinations"""
    
    @staticmethod
    def create_standard_transformer() -> Callable[[LogEntry], LogEntry]:
        """Create a standard transformer pipeline"""
        def transform(entry: LogEntry) -> LogEntry:
            return (LogTransformer.normalize_timestamp(entry)
                   .pipe(LogTransformer.normalize_level)
                   .pipe(LogTransformer.enrich_ip_data))
        return transform
    
    @staticmethod
    def create_security_transformer(
        mask_patterns: Optional[Dict[str, str]] = None
    ) -> Callable[[LogEntry], LogEntry]:
        """Create a security-focused transformer pipeline"""
        default_patterns = {
            'password': r'password["\s]*[:=]\s*["\']?\w+["\']?',
            'api_key': r'api[_-]key["\s]*[:=]\s*["\']?\w+["\']?',
            'token': r'token["\s]*[:=]\s*["\']?\w+["\']?',
            'secret': r'secret["\s]*[:=]\s*["\']?\w+["\']?'
        }
        
        patterns = mask_patterns or default_patterns
        
        def transform(entry: LogEntry) -> LogEntry:
            return (LogTransformer.normalize_timestamp(entry)
                   .pipe(LogTransformer.normalize_level)
                   .pipe(lambda e: LogTransformer.mask_sensitive_data(e, patterns))
                   .pipe(LogTransformer.enrich_ip_data))
        return transform
    
    @staticmethod
    def create_web_access_transformer() -> Callable[[LogEntry], LogEntry]:
        """Create a web access log transformer pipeline"""
        def transform(entry: LogEntry) -> LogEntry:
            return (LogTransformer.normalize_timestamp(entry)
                   .pipe(LogTransformer.normalize_level)
                   .pipe(LogTransformer.enrich_ip_data)
                   .pipe(LogTransformer.parse_user_agent))
        return transform

# Add method chaining support to LogEntry
def pipe(self, func: Callable[['LogEntry'], 'LogEntry']) -> 'LogEntry':
    """Chain transformation functions"""
    return func(self)

LogEntry.pipe = pipe