import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .field_detector import FieldDetector
from ..core.analyzer import LogAnalyzer
from ..parsers.base import LogEntry
from ..processors.pipeline import FilterStep, Pipeline

class LogProcessor:
    def __init__(self, analyzer: LogAnalyzer):
        self.analyzer = analyzer
        self.logger = logging.getLogger(__name__)
        self.field_detector = FieldDetector()

    def _process_entry(self, metrics: Dict[str, Any], entry: LogEntry) -> None:
        """Process a single log entry and update metrics"""
        # Get timestamp and hour
        hour = entry.timestamp.strftime("%Y-%m-%d %H:00")
        metrics["hourly_traffic"][hour] += 1
        
        # Process based on log type
        log_type = entry.metadata.get('log_type', '')
        
        if log_type == 'access':
            self._process_access_entry(metrics, entry, hour)
        elif log_type == 'error':
            self._process_error_entry(metrics, entry, hour)
        
    def _process_access_entry(self, metrics: Dict[str, Any], entry: LogEntry, hour: str) -> None:
        """Process access log entry"""
        data = entry.parsed_data
        
        # Process status code
        status_code = data.get('status_code')
        if status_code:
            status_group = f"{status_code//100}xx"
            metrics["status_codes"][status_group] += 1
            
            if status_code >= 400:
                metrics["error_count"] += 1
                metrics["hourly_errors"][hour] += 1
        
        # Process path
        path = data.get('path')
        if path and "paths" in metrics:
            metrics["paths"][path] += 1
        
        # Process endpoint from endpoint info if available
        endpoint_info = data.get('endpoint')
        if endpoint_info and isinstance(endpoint_info, dict):
            endpoint_path = endpoint_info.get('path')
            if endpoint_path and "endpoints" in metrics:
                metrics["endpoints"][endpoint_path] += 1
            
            # Process content category and request type
            if "content_types" in metrics and "category" in endpoint_info:
                metrics["content_types"][endpoint_info["category"]] += 1
                
            if "request_types" in metrics and "type" in endpoint_info:
                metrics["request_types"][endpoint_info["type"]] += 1

        # Process method
        method = data.get('method')
        if method and "methods" in metrics:
            metrics["methods"][method] += 1
        
        # Process IP
        ip = data.get('ip_address')
        if ip:
            if "unique_ips" in metrics:
                metrics["unique_ips"].add(ip)
            
            # Also update ip_requests if available
            if "ip_requests" in metrics:
                metrics["ip_requests"][ip] += 1
            
            if status_code in (401, 403, 404) and "failed_attempts" in metrics:
                metrics["failed_attempts"][ip] += 1
        
        # Process user agent
        user_agent = data.get('user_agent')
        if user_agent and "user_agents" in metrics:
            metrics["user_agents"][user_agent] += 1
        
        # Process user agent info
        if 'user_agent_info' in data and isinstance(data['user_agent_info'], dict):
            ua_info = data['user_agent_info']
            if ua_info.get('is_bot') and "bot_requests" in metrics and ip:
                metrics["bot_requests"][ip] += 1

        # Process response time
        bytes_sent = data.get('bytes_sent')
        if bytes_sent and isinstance(bytes_sent, (int, float)) and "response_times" in metrics:
            metrics["response_times"].append(bytes_sent)

            # Also update endpoint_times if path is available
            if path and "endpoint_times" in metrics:
                metrics["endpoint_times"][path].append(bytes_sent)

    def _process_error_entry(self, metrics: Dict[str, Any], entry: LogEntry, hour: str) -> None:
        """Process error log entry"""
        metrics["error_count"] += 1
        metrics["hourly_errors"][hour] += 1
        metrics["error_messages"][entry.message] += 1
        
        # Process error info if available
        data = entry.parsed_data
        error_info = data.get('error_info', {})
        if isinstance(error_info, dict):
            error_category = error_info.get('category', 'unknown')
            if "error_types" in metrics:
                metrics["error_types"][error_category] += 1
            
            # Track security-related errors
            if error_category == "security":
                client_ip = error_info.get('client_ip')
                if client_ip and "failed_attempts" in metrics:
                    metrics["failed_attempts"][client_ip] += 1
        
    def _initialize_metrics(self) -> Dict[str, Any]:
        return {
            # Basic metrics
            "total_entries": 0,
            "start_time": None,
            "end_time": None,
            
            # HTTP metrics
            "status_codes": defaultdict(int),
            "methods": defaultdict(int),
            "endpoints": defaultdict(int),
            "paths": defaultdict(int),
            "response_times": [],
            "endpoint_times": defaultdict(list),
            
            # Error metrics
            "error_count": 0,
            "error_types": defaultdict(int),
            "error_messages": defaultdict(int),
            "hourly_errors": defaultdict(int),
            
            # Security metrics
            "unique_ips": set(),
            "ip_requests": defaultdict(int),
            "failed_attempts": defaultdict(int),
            "user_agents": defaultdict(int),
            "bot_requests": defaultdict(int),
            
            # Traffic metrics
            "hourly_traffic": defaultdict(int),
            "content_types": defaultdict(int),
            "request_types": defaultdict(int)
        }
    
    async def process_files(
        self, 
        files: List[Dict[str, Any]], 
        parser_name: Optional[str] = None,
        filters: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Process multiple log files and aggregate the results"""
        self.logger.info(f"Starting to process {len(files)} files")
        metrics = self._initialize_metrics()
        successful_files = 0
        all_entries = []

        try:
            for file_info in files:
                try:
                    self.logger.info(f"Processing file {file_info['filename']}")
                    
                    # Add debug logging for parser
                    self.logger.debug(f"Using parser: {parser_name or 'auto-detect'}")
                    self.logger.debug(f"Available parsers: {list(self.analyzer.parser_factory._parsers.keys())}")
                    
                    # Try to analyze the file
                    file_results = self.analyzer.analyze_file(
                        file_info["path"],
                        parser_name=parser_name,
                        pipeline=None
                    )
                    
                    if file_results and "entries" in file_results:
                        entries = file_results["entries"]
                        self.logger.info(f"Found {len(entries)} entries in {file_info['filename']}")
                        
                        # Process each entry
                        for entry in entries:
                            if entry:  # Make sure entry is not None
                                metrics["total_entries"] += 1
                                # Update time range
                                timestamp = entry.timestamp
                                if not metrics["start_time"] or timestamp < metrics["start_time"]:
                                    metrics["start_time"] = timestamp
                                if not metrics["end_time"] or timestamp > metrics["end_time"]:
                                    metrics["end_time"] = timestamp
                                    
                                try:
                                    self._process_entry(metrics, entry)
                                except Exception as e:
                                    self.logger.warning(f"Error processing entry: {str(e)}")
                                    continue
                        
                        successful_files += 1
                    else:
                        self.logger.warning(f"No entries found in {file_info['filename']}")
                    
                except Exception as e:
                    self.logger.error(f"Error processing file {file_info['filename']}: {str(e)}", exc_info=True)
                    continue
                finally:
                    # Always try to cleanup
                    try:
                        Path(file_info["path"]).unlink(missing_ok=True)
                    except Exception as e:
                        self.logger.warning(f"Failed to delete temporary file {file_info['path']}: {str(e)}")

            # Even if there were errors in processing, try to return results if we have any entries
            if metrics['total_entries'] > 0:
                self.logger.info(f"Successfully processed {metrics['total_entries']} entries from {successful_files} files")
                
                # Detect fields
                detected_fields = {}
                if all_entries:
                    try:
                        detected_fields = self.field_detector.detect_fields(all_entries)
                        self.logger.info(f"Detected {len(detected_fields)} fields in the log entries")
                    except Exception as e:
                        self.logger.error(f"Error detecting fields: {str(e)}", exc_info=True)
                
                # Add detected fields to the results
                results = self._prepare_combined_results(metrics)
                results["detected_fields"] = detected_fields
                return results

            if successful_files == 0:
                available_parsers = list(self.analyzer.parser_factory._parsers.keys())
                raise ValueError(f"No files were successfully processed. Available parsers: {', '.join(available_parsers)}")

            self.logger.info(f"Successfully processed {metrics['total_entries']} entries from {successful_files} files")
            
            # Detect fields
            detected_fields = {}
            if all_entries:
                try:
                    detected_fields = self.field_detector.detect_fields(all_entries)
                    self.logger.info(f"Detected {len(detected_fields)} fields in the log entries")
                except Exception as e:
                    self.logger.error(f"Error detecting fields: {str(e)}", exc_info=True)
            
            # Add detected fields to the results
            results = self._prepare_combined_results(metrics)
            results["detected_fields"] = detected_fields
            return results
            
        except Exception as e:
            self.logger.error("Error in process_files", exc_info=True)
            raise

    # def _process_entries(self, metrics: Dict[str, Any], entries: List[LogEntry]) -> None:
    #     for entry in entries:
    #         # Update basic metrics
    #         metrics["total_entries"] += 1
            
    #         # Update time range
    #         timestamp = entry.timestamp
    #         if not metrics["start_time"] or timestamp < metrics["start_time"]:
    #             metrics["start_time"] = timestamp
    #         if not metrics["end_time"] or timestamp > metrics["end_time"]:
    #             metrics["end_time"] = timestamp

    #         # Update hourly traffic
    #         hour = timestamp.strftime("%Y-%m-%d %H:00")
    #         metrics["hourly_traffic"][hour] += 1

    #         parsed_data = entry.parsed_data
            
    #         # Process based on log type
    #         if entry.metadata.get("log_type") == "access":
    #             self._process_access_data(metrics, entry, parsed_data, hour)
    #         elif entry.metadata.get("log_type") == "error":
    #             self._process_error_data(metrics, entry, parsed_data, hour)

    # def _process_access_data(self, metrics: Dict[str, Any], entry: LogEntry, data: Dict[str, Any], hour: str) -> None:
    #     # Process status codes
    #     status_code = data.get('status_code')
    #     if status_code:
    #         status_group = f"{status_code//100}xx"
    #         metrics["status_codes"][status_group] += 1
            
    #         if status_code >= 400:
    #             metrics["error_count"] += 1
    #             metrics["hourly_errors"][hour] += 1
    #             metrics["error_messages"][entry.message] += 1

    #     # Process endpoints
    #     if 'endpoint' in data:
    #         endpoint_info = data['endpoint']
    #         path = endpoint_info['path']
    #         metrics["endpoints"][path] += 1
    #         metrics["content_types"][endpoint_info["category"]] += 1
    #         metrics["request_types"][endpoint_info["type"]] += 1

    #     # Process HTTP method
    #     method = data.get('method')
    #     if method:
    #         metrics["methods"][method] += 1

    #     # Process client info
    #     ip = data.get('ip_address')
    #     if ip:
    #         metrics["unique_ips"].add(ip)
    #         metrics["ip_requests"][ip] += 1
            
    #         if status_code in (401, 403, 404):
    #             metrics["failed_attempts"][ip] += 1

    #     # Process user agent info
    #     if 'user_agent_info' in data:
    #         ua_info = data['user_agent_info']
    #         ua_string = f"{ua_info.get('browser', 'unknown')} ({ua_info.get('device_type', 'unknown')})"
    #         metrics["user_agents"][ua_string] += 1
            
    #         if ua_info.get('is_bot'):
    #             metrics["bot_requests"][ip] += 1

    #     # Process performance metrics
    #     bytes_sent = data.get('bytes_sent')
    #     if bytes_sent and isinstance(bytes_sent, (int, float)):
    #         metrics["response_times"].append(bytes_sent)
    #         if path:
    #             metrics["endpoint_times"][path].append(bytes_sent)

    # def _process_error_data(self, metrics: Dict[str, Any], entry: LogEntry, data: Dict[str, Any], hour: str) -> None:
    #     metrics["error_count"] += 1
    #     metrics["hourly_errors"][hour] += 1
        
    #     # Process error info
    #     error_info = data.get('error_info', {})
    #     error_category = error_info.get('category', 'unknown')
    #     metrics["error_types"][error_category] += 1
    #     metrics["error_messages"][entry.message] += 1
        
    #     # Track security-related errors
    #     if error_category == "security":
    #         client_ip = error_info.get('client_ip')
    #         if client_ip:
    #             metrics["failed_attempts"][client_ip] += 1

    def _prepare_combined_results(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare final analysis results from collected metrics
        
        Args:
            metrics: The metrics dictionary with raw data
            
        Returns:
            Structured results dictionary for the API response
        """
        try:
            total_entries = metrics.get("total_entries", 0)
            if total_entries == 0:
                return self._get_empty_results()

            # Calculate basic rates
            error_count = metrics.get("error_count", 0)
            error_rate = (error_count / total_entries * 100) if total_entries > 0 else 0
            
            response_times = metrics.get("response_times", [])
            avg_response = int(sum(response_times) / len(response_times)) if response_times else 0
            
            # Calculate time-based metrics
            start_time = metrics.get("start_time")
            end_time = metrics.get("end_time")
            duration_seconds = (end_time - start_time).total_seconds() if start_time and end_time else 3600

            return {
                'summary': {
                    'total_entries': total_entries,
                    'error_rate': f"{error_rate:.1f}%",
                    'average_response_time': f"{avg_response}ms",
                    'unique_ips': len(metrics.get("unique_ips", set())),
                    'date_range': self._get_date_range(metrics)
                },
                'http_analysis': {
                    'status_distribution': dict(metrics.get("status_codes", {})),
                    'http_methods': dict(metrics.get("methods", {})),
                    'top_endpoints': self._get_top_endpoints(metrics),
                    'content_types': dict(metrics.get("content_types", {})),
                    'request_types': dict(metrics.get("request_types", {}))
                },
                'error_analysis': {
                    'error_types': dict(metrics.get("error_types", {})),
                    'error_timeline': {
                        'error_trends': self._get_error_trends(metrics)
                    },
                    'top_error_patterns': self._get_error_patterns(metrics)
                },
                'security_analysis': {
                    'ip_statistics': {
                        'unique_ips': len(metrics.get("unique_ips", set())),
                        'suspicious_ips': self._get_suspicious_ips(metrics),
                        'bot_activity': dict(metrics.get("bot_requests", {}))
                    },
                    'user_agents': self._get_user_agents(metrics, total_entries)
                },
                'performance_metrics': {
                    'response_times': self._get_response_times(metrics),
                    'throughput': {
                        'requests_per_second': float(f"{total_entries/duration_seconds:.2f}") if duration_seconds > 0 else 0,
                        'peak_hour': self._get_peak_hour(metrics.get("hourly_traffic", {}))
                    },
                    'slow_endpoints': self._get_slow_endpoints(metrics)
                },
                'time_analysis': {
                    'peak_times': self._get_peak_times(metrics),
                    'timeline': {
                        'average_rate': {
                            'per_second': float(f"{total_entries/duration_seconds:.2f}") if duration_seconds > 0 else 0,
                            'per_minute': float(f"{total_entries/(duration_seconds/60):.2f}") if duration_seconds > 0 else 0,
                            'per_hour': float(f"{total_entries/(duration_seconds/3600):.2f}") if duration_seconds > 0 else 0
                        }
                    }
                }
            }
        except Exception as e:
            self.logger.error(f"Error preparing results: {str(e)}", exc_info=True)
            return self._get_empty_results()

    def _get_peak_hour(self, hourly_counts: Dict[str, int]) -> Dict[str, Any]:
        """Get the hour with highest traffic
        
        Args:
            hourly_counts: Dictionary mapping hours to request counts
            
        Returns:
            Dictionary with peak hour information
        """
        try:
            if not hourly_counts:
                return {"hour": "N/A", "requests": 0}
                    
            peak_hour = max(hourly_counts.items(), key=lambda x: x[1], default=("N/A", 0))
            return {
                "hour": peak_hour[0],
                "requests": peak_hour[1]
            }
        except Exception as e:
            self.logger.warning(f"Error calculating peak hour: {str(e)}")
            return {"hour": "N/A", "requests": 0}

    def _get_date_range(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Get the date range of the analyzed logs
        
        Args:
            metrics: The metrics dictionary
            
        Returns:
            Dictionary with start, end, and duration information
        """
        try:
            if not metrics["start_time"] or not metrics["end_time"]:
                return {
                    'start': 'N/A',
                    'end': 'N/A',
                    'duration': 'N/A'
                }
                    
            duration = metrics["end_time"] - metrics["start_time"]
                
            return {
                'start': metrics["start_time"].strftime('%Y-%m-%d %H:%M:%S'),
                'end': metrics["end_time"].strftime('%Y-%m-%d %H:%M:%S'),
                'duration': str(duration)
            }
        except Exception as e:
            self.logger.warning(f"Error calculating date range: {str(e)}")
            return {
                'start': 'N/A',
                'end': 'N/A',
                'duration': 'N/A'
            }

    def _get_top_endpoints(self, metrics: Dict[str, Any], limit: int = 10) -> list:
        """Get top endpoints by request count
        
        Args:
            metrics: The metrics dictionary
            limit: Maximum number of endpoints to return
            
        Returns:
            List of top endpoints with request counts
        """
        try:
            if "paths" not in metrics or not metrics["paths"]:
                return []
                
            endpoint_counts = metrics["paths"]
                
            return [
                {'endpoint': endpoint, 'requests': count}
                for endpoint, count in sorted(
                    endpoint_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:limit]
            ]
        except Exception as e:
            self.logger.warning(f"Error getting top endpoints: {str(e)}")
            return []

    def _get_error_trends(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get error trends over time
        
        Args:
            metrics: The metrics dictionary
            
        Returns:
            List of error trends by hour
        """
        try:
            hourly_errors = metrics.get("hourly_errors", {})
            if not hourly_errors:
                return []
                
            total_entries = metrics.get("total_entries", 1)  # Avoid division by zero
            
            # Create error trends
            sorted_hours = sorted(hourly_errors.items())
            return [
                {
                    'hour': hour,
                    'count': count,
                    'rate': f"{(count / total_entries * 100):.1f}%" if total_entries > 0 else "0%"
                }
                for hour, count in sorted_hours[-24:]  # Last 24 hours or less
            ]
        except Exception as e:
            self.logger.warning(f"Error calculating error trends: {str(e)}")
            return []
            
    def _get_error_patterns(self, metrics: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
        """Get the most common error patterns
        
        Args:
            metrics: The metrics dictionary
            limit: Maximum number of patterns to return
            
        Returns:
            List of error patterns with counts
        """
        try:
            error_messages = metrics.get("error_messages", {})
            if not error_messages:
                return []
                
            error_count = metrics.get("error_count", 0)
            
            # Sort error patterns by frequency
            sorted_patterns = sorted(
                error_messages.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
            
            # Format the results
            return [
                {
                    'pattern': pattern,
                    'count': count,
                    'percentage': f"{(count / error_count * 100):.1f}%" if error_count > 0 else "0%"
                }
                for pattern, count in sorted_patterns
            ]
        except Exception as e:
            self.logger.warning(f"Error analyzing error patterns: {str(e)}")
            return []

    def _get_suspicious_ips(self, metrics: Dict[str, Any], threshold: int = 5) -> List[Dict[str, Any]]:
        """Get list of suspicious IPs based on failed attempts
        
        Args:
            metrics: The metrics dictionary
            threshold: Threshold for suspicious activity
            
        Returns:
            List of suspicious IPs with details
        """
        try:
            suspicious_ips = []
            
            failed_attempts = metrics.get("failed_attempts", {})
            ip_requests = metrics.get("ip_requests", {})
            
            if not failed_attempts:
                return []
            
            for ip, attempts in failed_attempts.items():
                if attempts >= threshold:
                    total_requests = ip_requests.get(ip, 0)
                    failure_rate = (attempts / total_requests * 100) if total_requests > 0 else 0
                    
                    suspicious_ips.append({
                        'ip': ip,
                        'failed_attempts': attempts,
                        'total_requests': total_requests,
                        'failure_rate': f"{failure_rate:.1f}%"
                    })
            
            # Sort by number of failed attempts
            return sorted(suspicious_ips, key=lambda x: x['failed_attempts'], reverse=True)
        except Exception as e:
            self.logger.warning(f"Error analyzing suspicious IPs: {str(e)}")
            return []

    def _get_user_agents(self, metrics: Dict[str, Any], total_entries: int) -> List[Dict[str, Any]]:
        """Get the most common user agents
        
        Args:
            metrics: The metrics dictionary
            total_entries: Total number of log entries
            
        Returns:
            List of user agents with counts
        """
        try:
            user_agents = metrics.get("user_agents", {})
            if not user_agents:
                return []

            # Sort user agents by frequency
            sorted_agents = sorted(
                user_agents.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]  # Top 10 user agents

            # Calculate total user agent count for percentages
            total_requests = sum(user_agents.values())

            # Format the results
            return [
                {
                    'user_agent': agent,
                    'count': count,
                    'percentage': f"{(count / total_requests * 100):.1f}%" if total_requests > 0 else "0%"
                }
                for agent, count in sorted_agents
            ]
        except Exception as e:
            self.logger.warning(f"Error analyzing user agents: {str(e)}")
            return []

    def _get_response_times(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Calculate response time statistics
        
        Args:
            metrics: The metrics dictionary
            
        Returns:
            Dictionary of response time statistics
        """
        try:
            response_times = metrics.get("response_times", [])
            if not response_times:
                return {
                    'average': "0ms",
                    'p95': "0ms",
                    'p99': "0ms",
                    'max': "N/A"
                }
                
            sorted_times = sorted(response_times)
            avg_time = sum(sorted_times) / len(sorted_times)
            
            # Calculate percentiles
            p95_index = int(len(sorted_times) * 0.95)
            p99_index = int(len(sorted_times) * 0.99)
            
            return {
                'average': f"{avg_time:.0f}ms",
                'p95': f"{sorted_times[p95_index]:.0f}ms" if p95_index < len(sorted_times) else "0ms",
                'p99': f"{sorted_times[p99_index]:.0f}ms" if p99_index < len(sorted_times) else "0ms",
                'max': f"{max(sorted_times):.0f}ms" if sorted_times else "N/A"
            }
        except Exception as e:
            self.logger.warning(f"Error calculating response times: {str(e)}")
            return {
                'average': "0ms",
                'p95': "0ms",
                'p99': "0ms",
                'max': "N/A"
            }

    def _get_peak_times(self, metrics: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
        """Get peak traffic times
        
        Args:
            metrics: The metrics dictionary
            limit: Maximum number of peak times to return
            
        Returns:
            List of peak times with request counts
        """
        try:
            hourly_traffic = metrics.get("hourly_traffic", {})
            if not hourly_traffic:
                return []
                
            total_entries = metrics.get("total_entries", 1)  # Avoid division by zero
            
            # Sort by request count descending
            peak_hours = sorted(
                hourly_traffic.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
            
            return [
                {
                    'hour': hour,
                    'requests': count,
                    'percent_of_total': (count / total_entries * 100) if total_entries > 0 else 0
                }
                for hour, count in peak_hours
            ]
        except Exception as e:
            self.logger.warning(f"Error calculating peak times: {str(e)}")
            return []

    def _get_slow_endpoints(self, metrics: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
        """Get slowest endpoints by average response time
        
        Args:
            metrics: The metrics dictionary
            limit: Maximum number of endpoints to return
            
        Returns:
            List of slow endpoints with response times
        """
        try:
            endpoint_times = metrics.get("endpoint_times", {})
            if not endpoint_times:
                return []
                
            endpoint_stats = []
            for endpoint, times in endpoint_times.items():
                if not times:
                    continue
                    
                avg_time = sum(times) / len(times)
                endpoint_stats.append({
                    'endpoint': endpoint,
                    'average_time': f"{avg_time:.2f}ms",
                    'requests': len(times)
                })
            
            return sorted(endpoint_stats, key=lambda x: float(x['average_time'].rstrip('ms')), reverse=True)[:limit]
        except Exception as e:
            self.logger.warning(f"Error calculating slow endpoints: {str(e)}")
            return []

    def _get_empty_results(self) -> Dict[str, Any]:
        """Return empty results structure when no data is processed
        
        Returns:
            Empty results dictionary with default values
        """
        return {
            'summary': {
                'total_entries': 0,
                'error_rate': "0.0%",
                'average_response_time': "0ms",
                'unique_ips': 0,
                'date_range': {'start': 'N/A', 'end': 'N/A', 'duration': 'N/A'}
            },
            'http_analysis': {
                'status_distribution': {},
                'http_methods': {},
                'top_endpoints': [],
                'content_types': {},
                'request_types': {}
            },
            'error_analysis': {
                'error_types': {},
                'error_timeline': {'error_trends': []},
                'top_error_patterns': []
            },
            'security_analysis': {
                'ip_statistics': {
                    'unique_ips': 0,
                    'suspicious_ips': [],
                    'bot_activity': {}
                },
                'user_agents': []
            },
            'performance_metrics': {
                'response_times': {
                    'average': "0ms",
                    'p95': "0ms",
                    'p99': "0ms",
                    'max': "N/A"
                },
                'throughput': {
                    'requests_per_second': 0,
                    'peak_hour': {"hour": "N/A", "requests": 0}
                },
                'slow_endpoints': []
            },
            'time_analysis': {
                'peak_times': [],
                'timeline': {
                    'average_rate': {
                        'per_second': 0.00,
                        'per_minute': 0.00,
                        'per_hour': 0.00
                    }
                }
            }
        }