import os
from typing import Dict, List

# File reading settings
DEFAULT_CHUNK_SIZE = int(os.getenv("LOG_ANALYZER_CHUNK_SIZE", "8192"))
MAX_LINE_LENGTH = int(os.getenv("LOG_ANALYZER_MAX_LINE_LENGTH", "1048576"))  # 1MB

# Processing settings
DEFAULT_MAX_WORKERS = int(os.getenv("LOG_ANALYZER_MAX_WORKERS", "4"))
DEFAULT_QUEUE_SIZE = int(os.getenv("LOG_ANALYZER_QUEUE_SIZE", "1000"))
MAX_ERRORS_STORED = int(os.getenv("LOG_ANALYZER_MAX_ERRORS", "1000"))

# Timestamp formats
TIMESTAMP_FORMATS = [
    # ISO formats
    "%Y-%m-%dT%H:%M:%S.%fZ",  # 2024-02-14T15:48:31.999Z
    "%Y-%m-%dT%H:%M:%SZ",  # 2024-02-14T15:48:31Z
    "%Y-%m-%dT%H:%M:%S.%f%z",  # 2024-02-14T15:48:31.999+0000
    "%Y-%m-%dT%H:%M:%S%z",  # 2024-02-14T15:48:31+0000
    # Common log formats
    "%d/%b/%Y:%H:%M:%S %z",  # 14/Feb/2024:15:48:31 +0000
    "%Y-%m-%d %H:%M:%S.%f",  # 2024-02-14 15:48:31.999
    "%Y-%m-%d %H:%M:%S",  # 2024-02-14 15:48:31
    "%Y/%m/%d %H:%M:%S",  # 2024/02/14 15:48:31
    # Syslog formats
    "%b %d %H:%M:%S",  # Feb 14 15:48:31
    "%Y %b %d %H:%M:%S",  # 2024 Feb 14 15:48:31
]

# Log levels
LOG_LEVELS = {
    # Standard levels
    "EMERGENCY": 0,
    "ALERT": 1,
    "CRITICAL": 2,
    "ERROR": 3,
    "WARNING": 4,
    "NOTICE": 5,
    "INFO": 6,
    "DEBUG": 7,
    # Aliases
    "EMERG": 0,
    "CRIT": 2,
    "ERR": 3,
    "WARN": 4,
    "NOTICE": 5,
    "INFO": 6,
    "DEBUG": 7,
}

# Level normalization mapping
LEVEL_MAPPING = {
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
    "CRIT": "CRITICAL",
    "ERR": "ERROR",
    "WARN": "WARNING",
    "NOTICE": "INFO",
    "TRACE": "DEBUG",
    "FINE": "DEBUG",
    "FINER": "DEBUG",
    "FINEST": "DEBUG",
}

# HTTP Status code categories
HTTP_STATUS_CATEGORIES = {
    "1xx": "Informational",
    "2xx": "Success",
    "3xx": "Redirection",
    "4xx": "Client Error",
    "5xx": "Server Error",
}

# Common log fields
COMMON_LOG_FIELDS = {
    # General fields
    "timestamp": ["timestamp", "time", "date", "@timestamp"],
    "level": ["level", "severity", "log_level", "priority"],
    "message": ["message", "msg", "log_message", "description"],
    "logger": ["logger", "logger_name", "source"],
    # Error fields
    "error": ["error", "error_message", "exception", "stack_trace"],
    "error_type": ["error_type", "exception_class", "exception_type"],
    "error_code": ["error_code", "status_code", "response_code"],
    # Web server fields
    "ip": ["ip", "ip_address", "client_ip", "remote_addr"],
    "method": ["method", "http_method", "request_method"],
    "path": ["path", "url", "uri", "request_uri"],
    "status": ["status", "status_code", "response_code"],
    "user_agent": ["user_agent", "http_user_agent", "browser"],
    "referer": ["referer", "http_referer", "referrer"],
    # Performance fields
    "duration": ["duration", "elapsed", "response_time", "latency"],
    "bytes": ["bytes", "bytes_sent", "response_size", "content_length"],
}

# Regular expressions for common patterns
REGEX_PATTERNS = {
    "ipv4": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    "ipv6": r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "url": r"https?://(?:[\w-]+\.)+[\w-]+(?:/[\w-./?%&=]*)?",
    "uuid": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "mac_address": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    "datetime_iso": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
}

# Sensitive data patterns to mask
SENSITIVE_PATTERNS = {
    "password": r'password["\s]*[:=]\s*["\']?\w+["\']?',
    "api_key": r'api[_-]key["\s]*[:=]\s*["\']?\w+["\']?',
    "token": r'token["\s]*[:=]\s*["\']?\w+["\']?',
    "secret": r'secret["\s]*[:=]\s*["\']?\w+["\']?',
    "access_key": r'access[_-]key["\s]*[:=]\s*["\']?\w+["\']?',
    "ssh_key": r"(?:ssh-rsa|ssh-dss|ecdsa-[^\s]+)\s+[A-Za-z0-9+/]+[=]{0,3}\s*(?:[^@\s]+@[^@\s]+)?",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "social_security": r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
}

# File extensions mapping
FILE_EXTENSIONS = {
    "log": "text/plain",
    "txt": "text/plain",
    "json": "application/json",
    "gz": "application/gzip",
    "zip": "application/zip",
}

# Default metric aggregation intervals
TIME_INTERVALS = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
    "month": 2592000,
}

# Error categories
ERROR_CATEGORIES = {
    "parser": ["ParserError", "ValueError", "KeyError", "TypeError"],
    "io": ["IOError", "FileNotFoundError", "PermissionError"],
    "memory": ["MemoryError", "OverflowError"],
    "timeout": ["TimeoutError", "ConnectionTimeoutError"],
}

# Default configuration
DEFAULT_CONFIG = {
    "parsing": {
        "max_line_length": MAX_LINE_LENGTH,
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "ignore_blank_lines": True,
        "ignore_comments": True,
        "comment_char": "#",
    },
    "processing": {
        "max_workers": DEFAULT_MAX_WORKERS,
        "queue_size": DEFAULT_QUEUE_SIZE,
        "batch_size": 1000,
        "timeout": 30,
    },
    "analysis": {
        "calculate_metrics": True,
        "track_unique_values": True,
        "max_unique_values": 10000,
        "time_zone": "UTC",
    },
    "output": {
        "max_errors": MAX_ERRORS_STORED,
        "include_raw_data": False,
        "pretty_print": True,
    },
}

# Environment variable mapping
ENV_VARS = {
    "LOG_ANALYZER_MAX_WORKERS": ("processing.max_workers", int),
    "LOG_ANALYZER_CHUNK_SIZE": ("parsing.chunk_size", int),
    "LOG_ANALYZER_MAX_LINE_LENGTH": ("parsing.max_line_length", int),
    "LOG_ANALYZER_QUEUE_SIZE": ("processing.queue_size", int),
    "LOG_ANALYZER_BATCH_SIZE": ("processing.batch_size", int),
    "LOG_ANALYZER_TIMEOUT": ("processing.timeout", int),
    "LOG_ANALYZER_MAX_ERRORS": ("output.max_errors", int),
    "LOG_ANALYZER_TIME_ZONE": ("analysis.time_zone", str),
    "LOG_ANALYZER_DEBUG": ("output.pretty_print", bool),
}
