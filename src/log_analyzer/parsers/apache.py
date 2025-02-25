import logging
import re
from datetime import datetime
from typing import Optional, Dict, Any
from .base import BaseParser, LogEntry, ParserError

class ApacheLogParser(BaseParser):
    """Parser for Apache/HTTPD access logs"""

    # More lenient pattern to handle incomplete lines
    PATTERN = (
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[\w:/]+\s[+\-]\d{4})\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d+) (?P<bytes>\S+)(?: "(?P<referer>(?:[^"]|\\")*)" "(?P<user_agent>(?:[^"]|\\")*)")?'
    )

    HTTP_METHODS = {
        'GET': 'read',
        'POST': 'write',
        'PUT': 'write',
        'DELETE': 'write',
        'HEAD': 'read',
        'OPTIONS': 'read',
        'PATCH': 'write'
    }

    # Enhanced file type categorization
    FILE_CATEGORIES = {
        'image': ['jpg', 'jpeg', 'png', 'gif', 'ico', 'svg', 'webp'],
        'asset': ['css', 'js', 'map', 'woff', 'woff2', 'ttf', 'eot'],
        'document': ['html', 'htm', 'pdf', 'doc', 'docx', 'txt', 'md'],
        'data': ['json', 'xml', 'csv', 'yaml', 'yml'],
        'media': ['mp4', 'mp3', 'avi', 'mov', 'wmv', 'flv', 'webm']
    }

    def __init__(self):
        self.regex = re.compile(self.PATTERN)
        self.logger = logging.getLogger(__name__)
        # Create reverse mapping for file extensions
        self.extension_categories = {}
        for category, extensions in self.FILE_CATEGORIES.items():
            for ext in extensions:
                self.extension_categories[ext] = category

    def supports_format(self, line: str) -> bool:
        """Check if line matches Apache log format"""
        try:
            line = line.strip()
            if not line:
                return False
            return bool(self.regex.match(line))
        except Exception:
            return False

    def _classify_endpoint(self, path: str) -> Dict[str, Any]:
        """Classify endpoint type and extract parameters"""
        endpoint_info = {
            "path": path,
            "type": "static",
            "parameters": [],
            "extension": None,
            "category": "other",
            "is_api": False,
            "query_params": {},
            "path_segments": []
        }

        try:
            # Split path and query
            if '?' in path:
                path_part, query_part = path.split('?', 1)
                endpoint_info["type"] = "dynamic"
                # Parse query parameters
                endpoint_info["query_params"] = dict(
                    param.split('=', 1) if '=' in param else (param, '')
                    for param in query_part.split('&')
                )
            else:
                path_part = path

            # Get path segments
            endpoint_info["path_segments"] = [s for s in path_part.split('/') if s]

            # Get file extension
            if '.' in path_part.split('/')[-1]:
                extension = path_part.split('.')[-1].lower()
                endpoint_info["extension"] = extension
                endpoint_info["category"] = self.extension_categories.get(extension, "other")

            # Check for API patterns
            if any(segment in ['api', 'rest', 'graphql', 'v1', 'v2', 'v3'] for segment in endpoint_info["path_segments"]):
                endpoint_info["type"] = "api"
                endpoint_info["is_api"] = True
                endpoint_info["category"] = "api"

        except Exception as e:
            self.logger.warning(f"Error classifying endpoint: {str(e)}")

        return endpoint_info

    def _analyze_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """Extract detailed information from user agent string"""
        ua_info = {
            "browser": "unknown",
            "browser_version": None,
            "device_type": "unknown",
            "os": "unknown",
            "os_version": None,
            "is_bot": False,
            "bot_name": None,
            "is_mobile": False
        }

        try:
            # Handle None or empty user agents
            if not user_agent or user_agent == '-':
                return ua_info
            
            user_agent_lower = user_agent.lower()

            # Detect bots
            bot_patterns = [
                (r'googlebot(?:/(\d+\.\d+))?', 'Googlebot'),
                (r'bingbot(?:/(\d+\.\d+))?', 'Bingbot'),
                (r'yandexbot(?:/(\d+\.\d+))?', 'Yandexbot'),
                (r'baiduspider(?:/(\d+\.\d+))?', 'Baiduspider'),
                (r'crawler|spider|bot(?:/(\d+\.\d+))?', 'Generic Bot')
            ]

            for pattern, bot_name in bot_patterns:
                match = re.search(pattern, user_agent_lower)
                if match:
                    ua_info["is_bot"] = True
                    ua_info["bot_name"] = bot_name
                    ua_info["device_type"] = "bot"
                    if match.group(1):
                        ua_info["browser_version"] = match.group(1)
                    break

            if not ua_info["is_bot"]:
                # Detect browsers
                if 'chrome' in user_agent_lower:
                    ua_info["browser"] = "Chrome"
                    chrome_ver = re.search(r'chrome/(\d+\.\d+)', user_agent_lower)
                    if chrome_ver:
                        ua_info["browser_version"] = chrome_ver.group(1)
                elif 'firefox' in user_agent_lower:
                    ua_info["browser"] = "Firefox"
                    ff_ver = re.search(r'firefox/(\d+\.\d+)', user_agent_lower)
                    if ff_ver:
                        ua_info["browser_version"] = ff_ver.group(1)
                elif 'safari' in user_agent_lower:
                    ua_info["browser"] = "Safari"
                    safari_ver = re.search(r'version/(\d+\.\d+)', user_agent_lower)
                    if safari_ver:
                        ua_info["browser_version"] = safari_ver.group(1)

                # Detect OS
                if 'windows' in user_agent_lower:
                    ua_info["os"] = "Windows"
                    win_ver = re.search(r'windows nt (\d+\.\d+)', user_agent_lower)
                    if win_ver:
                        ua_info["os_version"] = win_ver.group(1)
                elif 'mac os x' in user_agent_lower:
                    ua_info["os"] = "MacOS"
                    mac_ver = re.search(r'mac os x (\d+[._]\d+)', user_agent_lower)
                    if mac_ver:
                        ua_info["os_version"] = mac_ver.group(1).replace('_', '.')
                elif 'linux' in user_agent_lower:
                    ua_info["os"] = "Linux"
                elif 'android' in user_agent_lower:
                    ua_info["os"] = "Android"
                    android_ver = re.search(r'android (\d+\.\d+)', user_agent_lower)
                    if android_ver:
                        ua_info["os_version"] = android_ver.group(1)
                elif 'ios' in user_agent_lower:
                    ua_info["os"] = "iOS"
                    ios_ver = re.search(r'ios (\d+\.\d+)', user_agent_lower)
                    if ios_ver:
                        ua_info["os_version"] = ios_ver.group(1)

                # Detect device type
                ua_info["is_mobile"] = any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])
                if ua_info["is_mobile"]:
                    if 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
                        ua_info["device_type"] = "tablet"
                    else:
                        ua_info["device_type"] = "mobile"
                else:
                    ua_info["device_type"] = "desktop"

        except Exception as e:
            self.logger.warning(f"Error analyzing user agent: {str(e)}")

        return ua_info

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse an Apache log line into structured data"""
        try:
            # Handle empty or malformed lines
            line = line.strip()
            if not line:
                return None

            # Handle incomplete lines
            if line.endswith('"') or line.endswith('\\'):
                line = line + '" "-"'

            match = self.regex.match(line)
            if not match:
                self.logger.debug(f"Line does not match Apache format: {line}")
                return None

            data = match.groupdict()

            # Set defaults for missing fields
            data = {
                'ip': data.get('ip', '-'),
                'timestamp': data.get('timestamp', ''),
                'method': data.get('method', ''),
                'path': data.get('path', ''),
                'protocol': data.get('protocol', ''),
                'status': data.get('status', '0'),
                'bytes': data.get('bytes', '0'),
                'referer': data.get('referer', '-'),
                'user_agent': data.get('user_agent', '-')
            }

            # Parse timestamp
            timestamp = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")

            # Parse numeric values
            bytes_sent = int(data["bytes"]) if data["bytes"] != "-" else 0
            status_code = int(data["status"])
            
            # Get enhanced information
            endpoint_info = self._classify_endpoint(data["path"])
            ua_info = self._analyze_user_agent(data["user_agent"])

            # Prepare parsed data
            parsed_data = {
                "ip_address": data["ip"],
                "method": data["method"],
                "method_type": self.HTTP_METHODS.get(data["method"], "unknown"),
                "path": data["path"],
                "endpoint": endpoint_info,
                "protocol": data["protocol"],
                "status_code": status_code,
                "status_category": f"{status_code//100}xx",
                "bytes_sent": bytes_sent,
                "referer": data["referer"],
                "user_agent": data["user_agent"],
                "user_agent_info": ua_info
            }

            # Prepare metadata
            metadata = {
                "log_type": "access",
                "server_type": "apache",
                "request_type": endpoint_info["type"],
                "content_category": endpoint_info["category"],
                "is_error": status_code >= 400,
                "is_bot_request": ua_info["is_bot"],
                "device_type": ua_info["device_type"],
                "is_mobile": ua_info["is_mobile"],
                "is_api_request": endpoint_info["is_api"]
            }

            return LogEntry(
                timestamp=timestamp,
                level="ERROR" if status_code >= 400 else "INFO",
                message=f"{data['method']} {data['path']} - {status_code}",
                source="apache",
                raw_data=line,
                parsed_data=parsed_data,
                metadata=metadata
            )

        except Exception as e:
            self.logger.warning(f"Error parsing line: {str(e)}")
            return None

class ApacheErrorLogParser(BaseParser):
    """Parser for Apache/HTTPD error logs"""

    PATTERN = r"\[(?P<timestamp>[\w\s:]+)\] \[(?P<level>\w+)\] (?P<message>.*)"

    ERROR_CATEGORIES = {
        "client": ["client", "denied", "forbidden", "unauthorized"],
        "server": ["internal", "server", "timeout", "unavailable"],
        "security": ["permission", "ssl", "access", "auth"],
        "config": ["config", "syntax", "module"],
        "connection": ["connection", "socket", "protocol"]
    }

    def __init__(self):
        self.regex = re.compile(self.PATTERN)
        self.logger = logging.getLogger(__name__)

    def supports_format(self, line: str) -> bool:
        """Check if line matches Apache error log format"""
        try:
            line = line.strip()
            if not line:
                return False
            return bool(self.regex.match(line))
        except Exception:
            return False

    def _categorize_error(self, message: str, level: str) -> Dict[str, Any]:
        """Categorize error message and extract additional details"""
        try:
            message_lower = message.lower()
            
            # Determine error category
            error_category = "other"
            for category, keywords in self.ERROR_CATEGORIES.items():
                if any(keyword in message_lower for keyword in keywords):
                    error_category = category
                    break

            # Extract additional information
            error_info = {
                "category": error_category,
                "severity": level,
                "has_stack_trace": "stack trace" in message_lower or "traceback" in message_lower,
                "related_file": None,
                "client_ip": None,
                "error_code": None,
                "process_id": None,
                "thread_id": None
            }

            # Try to extract file paths
            file_patterns = [
                r'(?:file|path|config)\s*[\'"](/[^\'"]+)[\'"]',
                r'(?:reading|writing|accessing)\s+(\S+)',
                r'(?:in|from)\s+file\s+(\S+)'
            ]
            for pattern in file_patterns:
                file_match = re.search(pattern, message)
                if file_match:
                    error_info["related_file"] = file_match.group(1)
                    break

            # Try to extract IP addresses
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
            if ip_match:
                error_info["client_ip"] = ip_match.group(0)

            # Try to extract error codes
            error_code_match = re.search(r'error(?:\s+code)?\s*[:#]?\s*(\d+)', message_lower)
            if error_code_match:
                error_info["error_code"] = error_code_match.group(1)

            # Try to extract process/thread IDs
            pid_match = re.search(r'(?:pid|process)[:=\s]+(\d+)', message_lower)
            if pid_match:
                error_info["process_id"] = pid_match.group(1)

            tid_match = re.search(r'(?:tid|thread)[:=\s]+(\d+)', message_lower)
            if tid_match:
                error_info["thread_id"] = tid_match.group(1)

            return error_info

        except Exception as e:
            self.logger.warning(f"Error categorizing error message: {str(e)}")
            return {
                "category": "other",
                "severity": level,
                "has_stack_trace": False,
                "related_file": None,
                "client_ip": None
            }

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse an Apache error log line"""
        try:
            line = line.strip()
            if not line:
                return None

            match = self.regex.match(line)
            if not match:
                self.logger.debug(f"Line does not match Apache error format: {line}")
                return None

            data = match.groupdict()

            # Parse timestamp
            try:
                timestamp = datetime.strptime(data["timestamp"], "%a %b %d %H:%M:%S %Y")
            except ValueError:
                self.logger.warning(f"Invalid timestamp format: {data['timestamp']}")
                return None

            level = data["level"].upper()

            # Enhanced error analysis
            error_info = self._categorize_error(data["message"], level)

            parsed_data = {
                "error_message": data["message"],
                "error_info": error_info,
                "error_category": error_info["category"],
                "has_stack_trace": error_info["has_stack_trace"],
                "related_file": error_info["related_file"],
                "client_ip": error_info["client_ip"],
                "error_code": error_info["error_code"],
                "process_id": error_info["process_id"],
                "thread_id": error_info["thread_id"]
            }

            metadata = {
                "log_type": "error",
                "server_type": "apache",
                "error_severity": level,
                "error_category": error_info["category"],
                "is_security_related": error_info["category"] == "security",
                "has_file_reference": error_info["related_file"] is not None,
                "has_client_info": error_info["client_ip"] is not None,
                "has_process_info": error_info["process_id"] is not None or error_info["thread_id"] is not None
            }

            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=data["message"],
                source="apache",
                raw_data=line,
                parsed_data=parsed_data,
                metadata=metadata
            )

        except Exception as e:
            self.logger.warning(f"Error parsing error log line: {str(e)}")
            return None