from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Set, Optional
from dataclasses import dataclass

from ..parsers.base import LogEntry

@dataclass
class RequestMetric:
    endpoint: str
    status_code: int
    response_time: float
    timestamp: datetime
    ip: str
    user_id: Optional[str] = None
    user_agent: Optional[str] = None
    message: str = ""
    level: str = "INFO"
    service_name: Optional[str] = None
    trace_id: Optional[str] = None

class MetricsCollector:
    """Collects and aggregates metrics from log entries"""

    def __init__(self):
        """Initialize metrics collector"""
        self.reset()

    def reset(self) -> None:
        """Reset all metrics to initial state"""
        # Basic counters
        self._total_entries = 0
        self._error_count = 0
        self._errors: List[str] = []
        self._level_counts: Dict[str, int] = defaultdict(int)
        
        # Time tracking
        self._start_time = datetime.now()
        self._first_timestamp: datetime | None = None
        self._last_timestamp: datetime | None = None
        self._duration: timedelta | None = None
        self._log_duration: timedelta | None = None
        self._processing_duration: timedelta | None = None
        self._hourly_counts: Dict[str, int] = defaultdict(int)
        
        # HTTP specific metrics
        self._http_methods: Dict[str, int] = defaultdict(int)
        self._endpoints: Dict[str, int] = defaultdict(int)  

        # Request tracking
        self._requests: List[RequestMetric] = []
        self._status_codes: Dict[str, int] = defaultdict(int)
        
        # IP tracking
        self._ip_requests: Dict[str, List[RequestMetric]] = defaultdict(list)
        self._failed_attempts: Dict[str, int] = defaultdict(int)
        self._unique_ips: Set[str] = set()
        self._suspicious_ips: Set[str] = set()  # IPs with high failure rates
        
        # Performance tracking
        self._response_times: List[float] = []
        self._endpoint_times: Dict[str, List[float]] = defaultdict(list)

        # Error tracking
        self._error_types: Dict[str, int] = defaultdict(int)
        self._error_patterns: Dict[str, int] = defaultdict(int)
        self._service_errors: Dict[str, int] = defaultdict(int)
        self._error_timestamps: List[datetime] = []
        
        # User agent tracking
        self._user_agents: Dict[str, int] = defaultdict(int)

    def _update_timestamps(self, timestamp: datetime) -> None:
        """Update timestamp tracking"""
        if not self._first_timestamp or timestamp < self._first_timestamp:
            self._first_timestamp = timestamp
        if not self._last_timestamp or timestamp > self._last_timestamp:
            self._last_timestamp = timestamp
            
        # Update hourly counts
        hour_key = timestamp.strftime('%Y-%m-%d %H:00')
        self._hourly_counts[hour_key] += 1
        
    def _process_syslog(self, entry: LogEntry) -> None:
        """Process syslog entries"""
        # Track error levels
        if entry.level in ('ERROR', 'CRITICAL', 'FATAL', 'SEVERE'):
            self._error_types[entry.level] += 1
            error_message = entry.message.strip()
            if error_message:
                self._error_patterns[error_message] += 1
        
        # Track services/programs
        service = entry.metadata.get('service', entry.source)
        if service:
            if entry.level in ('ERROR', 'CRITICAL', 'FATAL', 'SEVERE'):
                self._service_errors[service] += 1

    def _process_application_log(self, entry: LogEntry) -> None:
        """Process application log entries"""
        # Track error patterns and types
        if entry.level in ('ERROR', 'CRITICAL', 'FATAL', 'SEVERE'):
            self._error_types[entry.level] += 1
            error_message = entry.message.strip()
            if error_message:
                self._error_patterns[error_message] += 1
        
        # Track any performance metrics if available
        response_time = entry.parsed_data.get('response_time')
        if response_time:
            self._response_times.append(float(response_time))
        
        # Track service metrics
        service = entry.metadata.get('service', entry.source)
        if service:
            if entry.level in ('ERROR', 'CRITICAL', 'FATAL', 'SEVERE'):
                self._service_errors[service] += 1
                
    def _add_request_metric(self, entry: LogEntry) -> None:
        """Add a request metric from a log entry"""
        data = entry.parsed_data
        
        request = RequestMetric(
            endpoint=data.get('path', ''),
            status_code=data.get('status_code', 0),
            response_time=data.get('bytes_sent', 0),  # Using bytes as proxy for response time
            timestamp=entry.timestamp,
            ip=data.get('ip_address', ''),
            user_agent=data.get('user_agent'),
            message=entry.message,
            level=entry.level,
            service_name=entry.metadata.get('service')
        )
        
        self._requests.append(request)
        
        # Update IP request tracking
        if request.ip:
            self._ip_requests[request.ip].append(request)
            
    def process_entry(self, entry: LogEntry) -> None:
        """Process a single log entry and update metrics"""
        self._total_entries += 1
        self._level_counts[entry.level] += 1

        # Track errors with timestamps
        if entry.level in ('ERROR', 'CRITICAL', 'FATAL'):
            self._errors.append(entry.message)  # Store just the message
            self._error_timestamps.append(entry.timestamp)  # Store timestamp separately
            self._error_count += 1

        # Basic time tracking
        self._update_timestamps(entry.timestamp)

        # Process based on log type
        log_type = entry.metadata.get('log_type', 'unknown')
        
        if log_type == 'access':
            self._process_access_log(entry)
        elif log_type == 'error':
            self._process_error_log(entry)
        elif log_type == 'syslog':
            self._process_syslog(entry)
        elif log_type == 'application':
            self._process_application_log(entry)

    def _process_access_log(self, entry: LogEntry) -> None:
        """Process web server access log entry"""
        data = entry.parsed_data
        
        # Add request metric
        self._add_request_metric(entry)
        
        # Process endpoint info
        if 'endpoint' in data:
            endpoint_info = data['endpoint']
            path = endpoint_info['path']
            self._endpoints[path] += 1
            
            # Track response times by endpoint type
            if 'bytes_sent' in data:
                self._endpoint_times[path].append(data['bytes_sent'])
                self._response_times.append(data['bytes_sent'])
        
        # Process status codes
        status_code = data.get('status_code', 0)
        if status_code > 0:
            status_group = f"{status_code//100}xx"
            self._status_codes[status_group] += 1
            
            if status_code >= 400:
                self._error_count += 1
                self._errors.append(f"HTTP {status_code}: {entry.message}")
        
        # Process HTTP method
        method = data.get('method')
        if method:
            self._http_methods[method] += 1
        
        # Process client info
        ip = data.get('ip_address')
        if ip:
            self._unique_ips.add(ip)
            if status_code in (401, 403, 404):
                self._failed_attempts[ip] += 1
        
        # Process user agent
        if 'user_agent_info' in data:
            ua_info = data['user_agent_info']
            browser = ua_info.get('browser', 'unknown')
            device_type = ua_info.get('device_type', 'unknown')
            self._user_agents[f"{browser} ({device_type})"] += 1

    def _get_top_error_patterns(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the most common error patterns"""
        if not self._error_patterns:
            return []
            
        # Sort error patterns by frequency
        sorted_patterns = sorted(
            self._error_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        # Format the results
        return [
            {
                'pattern': pattern,
                'count': count,
                'percentage': f"{(count / self._error_count * 100):.1f}%" if self._error_count > 0 else "0%"
            }
            for pattern, count in sorted_patterns
        ]

    def _process_error_log(self, entry: LogEntry) -> None:
        """Process an error log entry"""
        self._error_count += 1
        
        # Track error level
        if entry.level:
            self._error_types[entry.level] += 1
        
        # Track error message pattern
        error_message = entry.message.strip()
        if error_message:
            self._error_patterns[error_message] += 1
        
        # Track service/component if available
        service = entry.metadata.get('service', 'unknown')
        if service:
            self._service_errors[service] += 1

    def _get_error_timeline(self) -> Dict[str, Any]:
        """Get timeline of errors with hourly distribution"""
        if not self._errors:
            return {
                'hourly_errors': {},
                'peak_error_time': 'N/A',
                'error_trends': []
            }
        
        # Track errors by hour
        hourly_errors = defaultdict(int)
        
        # Need to update how we store errors in process_entry
        for timestamp in self._error_timestamps:  # We'll create this list in process_entry
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
            hourly_errors[hour_key] += 1
        
        # Find peak error time
        if hourly_errors:
            peak_hour = max(hourly_errors.items(), key=lambda x: x[1])
        else:
            peak_hour = ('N/A', 0)
        
        # Create error trends (last 24 hours if available)
        sorted_hours = sorted(hourly_errors.items())
        error_trends = [
            {
                'hour': hour,
                'count': count,
                'rate': f"{(count / self._total_entries * 100):.1f}%" if self._total_entries > 0 else "0%"
            }
            for hour, count in sorted_hours[-24:]  # Last 24 hours
        ]
        
        return {
            'hourly_errors': dict(hourly_errors),
            'peak_error_time': {
                'hour': peak_hour[0],
                'count': peak_hour[1]
            },
            'error_trends': error_trends
        }

    def record_error(self, error: str) -> None:
        """Record a processing error"""
        self._errors.append(error)
        self._error_timestamps.append(datetime.now())

    def get_errors(self) -> List[str]:
        """Get list of recorded errors
        
        Returns:
            List of error messages
        """
        return self._errors

    def set_duration(self, duration: timedelta) -> None:
        """Set the processing duration"""
        self._duration = duration

    def _get_peak_hour(self) -> dict:
        """Get the hour with highest traffic"""
        if not self._hourly_counts:
            return {
                'hour': 'N/A',
                'requests': 0
            }
        
        peak_hour = max(self._hourly_counts.items(), key=lambda x: x[1])
        return {
            'hour': peak_hour[0],
            'requests': peak_hour[1]
        }

    def _detect_log_type(self) -> str:
        """Detect the type of log based on collected metrics"""
        # If we have HTTP status codes, it's likely a web server log
        if self._status_codes:
            if any(k.startswith('4') or k.startswith('5') for k in self._status_codes.keys()):
                return 'HTTP Access Log'
            return 'Web Server Log'
            
        # If we have error levels, it might be an error log
        if self._level_counts:
            error_levels = {'ERROR', 'CRITICAL', 'FATAL', 'SEVERE'}
            if any(level in error_levels for level in self._level_counts.keys()):
                return 'Error Log'
            if 'INFO' in self._level_counts or 'DEBUG' in self._level_counts:
                return 'Application Log'
                
        # If we have IP addresses but no status codes, might be a security log
        if self._unique_ips and not self._status_codes:
            return 'Security Log'

        # Default case
        return 'System Log'

    def _calculate_error_rate(self) -> float:
        """Calculate the error rate as a percentage"""
        if self._total_entries == 0:
            return 0.0
            
        # For HTTP logs
        if self._status_codes:
            error_requests = sum(
                count for status, count in self._status_codes.items()
                if status.startswith(('4', '5'))  # 4xx and 5xx status codes
            )
            return (error_requests / self._total_entries) * 100
            
        # For error logs / system logs
        if self._level_counts:
            error_entries = sum(
                count for level, count in self._level_counts.items()
                if level in ('ERROR', 'CRITICAL', 'FATAL', 'SEVERE')
            )
            return (error_entries / self._total_entries) * 100
            
        # Default - use error count
        return (self._error_count / self._total_entries) * 100

    def _calculate_request_rate(self, interval: str) -> float:
        """Calculate average requests per interval"""
        if not self._first_timestamp or not self._last_timestamp:
            return 0.0
            
        duration = (self._last_timestamp - self._first_timestamp).total_seconds()
        if duration == 0:
            return 0.0
            
        if interval == 'minute':
            return len(self._requests) / (duration / 60)
        elif interval == 'hour':
            return len(self._requests) / (duration / 3600)
        return 0.0

    def _get_success_rate(self) -> float:
        """Calculate success rate percentage"""
        total_status = sum(self._status_codes.values())
        if total_status == 0:
            return 100.0
            
        success_codes = sum(count for code, count in self._status_codes.items() 
                          if code.startswith('2'))
        return (success_codes / total_status) * 100

    def _get_error_rate(self) -> float:
        """Calculate error rate percentage"""
        total_status = sum(self._status_codes.values())
        if total_status == 0:
            return 0.0
            
        error_codes = sum(count for code, count in self._status_codes.items() 
                         if code.startswith(('4', '5')))
        return (error_codes / total_status) * 100

    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time in milliseconds"""
        if not self._response_times:
            return 0.0
            
        # Calculate average, handling possible empty list
        total_time = sum(self._response_times)
        total_requests = len(self._response_times)
        
        if total_requests == 0:
            return 0.0
            
        return total_time / total_requests

    def _get_avg_response_time(self) -> float:
        """Get average response time with fallback"""
        try:
            return self._calculate_avg_response_time()
        except Exception:
            return 0.0

    def _get_date_range(self) -> Dict[str, str]:
        """Get the date range of the analyzed logs"""
        try:
            if not self._first_timestamp or not self._last_timestamp:
                return {
                    'start': 'N/A',
                    'end': 'N/A',
                    'duration': 'N/A'
                }
                
            duration = self._last_timestamp - self._first_timestamp
            
            return {
                'start': self._first_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'end': self._last_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': str(duration)
            }
        except Exception:
            return {
                'start': 'N/A',
                'end': 'N/A',
                'duration': 'N/A'
            }

    def _get_percentile_response_time(self, percentile: int) -> float:
        """Calculate percentile response time"""
        if not self._response_times:
            return 0.0
            
        sorted_times = sorted(self._response_times)
        index = int(len(sorted_times) * (percentile / 100))
        return sorted_times[index]

    def _get_top_endpoints(self, limit: int = 10) -> list:
        """Get top endpoints by request count"""
        endpoint_counts = {}
        for request in self._requests:
            endpoint_counts[request.endpoint] = endpoint_counts.get(request.endpoint, 0) + 1
            
        return [{
            'endpoint': endpoint,
            'requests': count
        } for endpoint, count in sorted(
            endpoint_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]]

    def _get_top_failed_attempts(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get IPs with most failed attempts"""
        return [
            {'ip': ip, 'attempts': count}
            for ip, count in sorted(
                self._failed_attempts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
        ]

    def _get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IPs by request count"""
        ip_counts = {ip: len(requests) for ip, requests in self._ip_requests.items()}
        return [{
            'ip': ip,
            'requests': count
        } for ip, count in sorted(
            ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]]
    
    def _get_suspicious_ips(self, threshold: int = 5) -> List[Dict[str, Any]]:
        """Get list of suspicious IPs based on failed attempts and unusual activity"""
        suspicious_ips = []
        
        for ip, attempts in self._failed_attempts.items():
            if attempts >= threshold:
                total_requests = len(self._ip_requests.get(ip, []))
                failure_rate = (attempts / total_requests * 100) if total_requests > 0 else 0
                
                suspicious_ips.append({
                    'ip': ip,
                    'failed_attempts': attempts,
                    'total_requests': total_requests,
                    'failure_rate': f"{failure_rate:.1f}%"
                })
        
        # Sort by number of failed attempts
        return sorted(suspicious_ips, key=lambda x: x['failed_attempts'], reverse=True)
    
    def _detect_attack_patterns(self) -> Dict[str, Any]:
        """Detect potential attack patterns in the logs"""
        patterns = {
            'brute_force': [],     # Multiple failed login attempts
            'scan_attempts': [],    # Systematic scanning patterns
            'dos_attempts': []      # High frequency requests
        }
        
        # Detect brute force attempts (multiple failed logins from same IP)
        for ip, attempts in self._failed_attempts.items():
            if attempts >= 5:  # Threshold for suspicious activity
                patterns['brute_force'].append({
                    'ip': ip,
                    'attempts': attempts,
                    'timestamp': max(req.timestamp for req in self._ip_requests.get(ip, []))
                })
        
        # Detect scanning attempts (multiple 404s from same IP)
        scan_attempts = defaultdict(int)
        for ip, requests in self._ip_requests.items():
            not_found = sum(1 for req in requests if req.status_code == 404)
            if not_found >= 5:  # Threshold for scan detection
                patterns['scan_attempts'].append({
                    'ip': ip,
                    'not_found_count': not_found,
                    'total_requests': len(requests)
                })
        
        # Detect potential DoS attempts (high frequency requests)
        for ip, requests in self._ip_requests.items():
            if len(requests) >= 100:  # Threshold for high frequency
                patterns['dos_attempts'].append({
                    'ip': ip,
                    'request_count': len(requests),
                    'rate_per_minute': len(requests) / max(1, (self._last_timestamp - self._first_timestamp).total_seconds() / 60)
                })
        
        # Sort all patterns by severity
        patterns['brute_force'].sort(key=lambda x: x['attempts'], reverse=True)
        patterns['scan_attempts'].sort(key=lambda x: x['not_found_count'], reverse=True)
        patterns['dos_attempts'].sort(key=lambda x: x['request_count'], reverse=True)
        
        return {
            'detected_patterns': patterns,
            'total_suspicious_ips': len(set(
                [x['ip'] for x in patterns['brute_force']] +
                [x['ip'] for x in patterns['scan_attempts']] +
                [x['ip'] for x in patterns['dos_attempts']]
            ))
        }
    
    def _get_top_user_agents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most common user agents"""
        if not self._user_agents:
            return []

        # Sort user agents by frequency
        sorted_agents = sorted(
            self._user_agents.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]

        # Calculate total user agent count for percentages
        total_requests = sum(self._user_agents.values())

        # Format the results
        return [
            {
                'user_agent': agent,
                'count': count,
                'percentage': f"{(count / total_requests * 100):.1f}%" if total_requests > 0 else "0%"
            }
            for agent, count in sorted_agents
        ]

    def _calculate_percentile(self, percentile: int) -> float:
        """Calculate a percentile value from response times
        
        Args:
            percentile: The percentile to calculate (0-100)
            
        Returns:
            float: The calculated percentile value
        """
        if not self._response_times:
            return 0.0
            
        if not 0 <= percentile <= 100:
            raise ValueError("Percentile must be between 0 and 100")
            
        sorted_times = sorted(self._response_times)
        index = int((percentile / 100) * len(sorted_times))
        
        # Ensure index is within bounds
        if index == len(sorted_times):
            index -= 1
            
        return sorted_times[index]

    def _calculate_throughput(self, interval: str = 'second') -> float:
        """Calculate the average throughput over the log duration.
        
        Args:
            interval: Time interval ('second', 'minute', or 'hour')
            
        Returns:
            Average requests per interval
        """
        if not self._first_timestamp or not self._last_timestamp:
            return 0.0
            
        duration = self._last_timestamp - self._first_timestamp
        total_seconds = duration.total_seconds()
        
        if total_seconds == 0:
            return 0.0
            
        divisor = {
            'second': 1,
            'minute': 60,
            'hour': 3600
        }.get(interval, 1)
        
        return len(self._requests) / (total_seconds / divisor)

    def _get_hourly_distribution(self) -> Dict[str, int]:
        """Get the distribution of requests by hour.
        
        Returns:
            Dictionary mapping hour to request count
        """
        if not self._hourly_counts:
            return {}
            
        # Sort by hour
        return dict(sorted(self._hourly_counts.items()))

    def _get_peak_times(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """Get the peak traffic times.
        
        Args:
            top_n: Number of peak times to return
            
        Returns:
            List of peak times with request counts
        """
        if not self._hourly_counts:
            return []
            
        # Sort by request count descending
        peak_hours = sorted(
            self._hourly_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        return [
            {
                'hour': hour,
                'requests': count,
                'percent_of_total': (count / len(self._requests) * 100) if self._requests else 0
            }
            for hour, count in peak_hours
        ]

    def _get_timeline(self) -> Dict[str, Any]:
        """Get timeline analysis of requests.
        
        Returns:
            Dictionary containing timeline metrics
        """
        if not self._requests:
            return {
                'total_duration': None,
                'peak_times': self._get_peak_times(),
                'hourly_distribution': self._get_hourly_distribution(),
                'average_rate': {
                    'per_second': self._calculate_throughput('second'),
                    'per_minute': self._calculate_throughput('minute'),
                    'per_hour': self._calculate_throughput('hour')
                }
            }
            
        duration = self._last_timestamp - self._first_timestamp if self._first_timestamp and self._last_timestamp else None
        
        return {
            'total_duration': str(duration) if duration else None,
            'peak_times': self._get_peak_times(),
            'hourly_distribution': self._get_hourly_distribution(),
            'average_rate': {
                'per_second': self._calculate_throughput('second'),
                'per_minute': self._calculate_throughput('minute'),
                'per_hour': self._calculate_throughput('hour')
            }
        }

    def get_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results"""
        return {
            'summary': {
                'log_type': self._detect_log_type(),
                'total_entries': self._total_entries,
                'error_rate': f"{self._calculate_error_rate():.1f}%",
                'average_response_time': f"{self._calculate_avg_response_time():.0f}ms",
                'unique_ips': len(self._unique_ips),
                'date_range': self._get_date_range()
            },
            'http_analysis': {
                'status_distribution': dict(self._status_codes),
                'top_endpoints': self._get_top_endpoints(10),
                'http_methods': dict(self._http_methods),
                'average_response_time': self._calculate_avg_response_time(),
                'slowest_endpoints': self._get_slow_endpoints(5)
            },
            'error_analysis': {
                'error_types': dict(self._error_types),
                'top_error_patterns': self._get_top_error_patterns(5),
                'service_errors': dict(self._service_errors),
                'error_timeline': self._get_error_timeline()
            },
            'security_analysis': {
                'ip_statistics': {
                    'unique_ips': len(self._unique_ips),
                    'suspicious_ips': self._get_suspicious_ips(),
                    'top_requesters': self._get_top_ips(10)
                },
                'attack_patterns': {
                    'failed_attempts': dict(self._failed_attempts),
                    'suspicious_patterns': self._detect_attack_patterns()
                },
                'user_agents': self._get_top_user_agents(10)
            },
            'performance_metrics': {
                'response_times': {
                    'average': f"{self._calculate_avg_response_time():.0f}ms",
                    'p95': f"{self._calculate_percentile(95):.0f}ms",
                    'p99': f"{self._calculate_percentile(99):.0f}ms",
                    'max': f"{max(self._response_times):.0f}ms" if self._response_times else "N/A"
                },
                'throughput': {
                    'requests_per_second': self._calculate_throughput(),
                    'peak_hour': self._get_peak_hour()
                }
            },
            'time_analysis': {
                'hourly_distribution': self._get_hourly_distribution(),
                'peak_times': self._get_peak_times(),
                'timeline': self._get_timeline()
            }
        }
    
    def _get_time_analysis(self) -> Dict[str, Any]:
        peak_hour = max(self._hourly_counts.items(), key=lambda x: x[1], default=("N/A", 0))
        return {
            'hourly_distribution': dict(self._hourly_counts),
            'peak_hour': {
                'time': peak_hour[0],
                'requests': peak_hour[1]
            },
            'average_rate': f"{len(self._requests)/(self._last_timestamp - self._first_timestamp).total_seconds():.1f}/s" if self._first_timestamp else "N/A"
        }
    
    def _get_error_analysis(self) -> Dict[str, Any]:
        error_codes = {k: v for k, v in self._status_codes.items() if k[0] in ('4', '5')}
        return {
            'status_codes': dict(self._status_codes),
            'error_codes': error_codes,
            'error_rate': f"{sum(error_codes.values())/self._total_entries*100:.2f}%" if self._total_entries else "0%"
        }
    
    def _get_slow_endpoints(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get slowest endpoints by average response time"""
        if not self._endpoint_times:
            return []
            
        endpoint_stats = []
        for endpoint, times in self._endpoint_times.items():
            avg_time = sum(times) / len(times)
            endpoint_stats.append({
                'endpoint': endpoint,
                'average_time': f"{avg_time:.2f}ms",
                'requests': len(times)
            })
        
        return sorted(endpoint_stats, key=lambda x: float(x['average_time'].rstrip('ms')), reverse=True)[:limit]

    def _get_performance_analysis(self) -> Dict[str, Any]:
        if not self._response_times:
            return {'no_data': True}
            
        sorted_times = sorted(self._response_times)
        p50_index = int(len(sorted_times) * 0.50)
        p95_index = int(len(sorted_times) * 0.95)
        p99_index = int(len(sorted_times) * 0.99)
        
        return {
            'response_times': {
                'min': f"{min(sorted_times):.0f}ms",
                'max': f"{max(sorted_times):.0f}ms",
                'avg': f"{sum(sorted_times)/len(sorted_times):.0f}ms",
                'median': f"{sorted_times[p50_index]:.0f}ms",
                'p95': f"{sorted_times[p95_index]:.0f}ms",
                'p99': f"{sorted_times[p99_index]:.0f}ms"
            },
            'throughput': {
                'requests_per_second': f"{len(self._requests) / max(1, (self._last_timestamp - self._first_timestamp).total_seconds()):.2f}",
                'peak_hour': self._get_peak_hour()
            },
            'slow_endpoints': self._get_slow_endpoints(5)
        }
    
    def _get_security_analysis(self) -> Dict[str, Any]:
        failed_login_threshold = 5  # Consider IPs suspicious after 5 failed attempts
        
        suspicious_ips = {
            ip: attempts for ip, attempts in self._failed_attempts.items()
            if attempts >= failed_login_threshold
        }
        
        return {
            'overview': {
                'total_unique_ips': len(self._unique_ips),
                'suspicious_ips': len(suspicious_ips),
                'total_failed_attempts': sum(self._failed_attempts.values())
            },
            'failed_attempts': {
                'top_offenders': self._get_top_failed_attempts(5),
                'suspicious_ips': [
                    {'ip': ip, 'attempts': attempts}
                    for ip, attempts in sorted(
                        suspicious_ips.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )
                ]
            },
            'user_agents': dict(self._user_agent_stats)
        }

    def finish_processing(self) -> None:
        """Mark processing as complete and calculate final metrics"""
        if not self._duration:
            current_time = datetime.now()
            if self._first_timestamp and self._last_timestamp:
                self._log_duration = self._last_timestamp - self._first_timestamp
                self._processing_duration = current_time - self._start_time
        
        if not self._last_timestamp:
            self._last_timestamp = datetime.now()
        if not self._first_timestamp:
            self._first_timestamp = self._last_timestamp