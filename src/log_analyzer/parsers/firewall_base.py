import re
import logging
from datetime import datetime
from typing import Dict, Optional, List, Any, Tuple

from ..parsers.base import BaseParser, LogEntry, ParserError


class FirewallLogParser(BaseParser):
    """Base class for firewall log parsers"""

    def __init__(self):
        """Initialize firewall log parser"""
        self.name = "generic_firewall"
        self.description = "Generic Firewall Log Parser"
        self.logger = logging.getLogger(__name__)

    def supports_format(self, line: str) -> bool:
        """Check if the line is a supported firewall log format"""
        # This should be overridden by specific firewall parsers
        return False

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a firewall log line into structured data

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        # This should be overridden by specific firewall parsers
        raise NotImplementedError("Firewall parser must implement parse_line")

    def extract_ips(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and validate IP addresses from log data

        Args:
            log_data: Dictionary containing log data with SRC and DST fields

        Returns:
            Dictionary with validated and classified IP information
        """
        import ipaddress

        ip_info = {}

        for field in ["src", "dst"]:
            ip_str = log_data.get(field)
            if not ip_str:
                continue

            try:
                # Try to parse the IP address
                ip = ipaddress.ip_address(ip_str)
                ip_type = "ipv6" if ip.version == 6 else "ipv4"
                
                ip_info[f"{field}_ip_version"] = ip.version
                ip_info[f"{field}_ip_type"] = (
                    "private" if ip.is_private else "public"
                )
                ip_info[f"{field}_ip"] = str(ip)
                
            except ValueError:
                # If it's not a valid IP, just store the original string
                self.logger.debug(f"Invalid IP address format for {field}: {ip_str}")
                ip_info[f"{field}_ip"] = ip_str
                ip_info[f"{field}_ip_type"] = "unknown"

        return ip_info

    def extract_ports(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and categorize ports from log data

        Args:
            log_data: Dictionary containing log data with source and destination port fields

        Returns:
            Dictionary with port information and categorization
        """
        port_info = {}
        
        # Common port mappings
        well_known_ports = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3389: "RDP",
            1433: "SQL Server",
            3306: "MySQL",
            5432: "PostgreSQL",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            21: "FTP",
            20: "FTP Data",
            161: "SNMP",
            162: "SNMP Trap",
            389: "LDAP",
            636: "LDAPS",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            500: "IKE",
            4500: "IKE NAT-T",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt",
            3000: "Dev Server",
            5000: "Dev Server",
            8000: "Dev Server",
            8888: "Dev Server",
            9000: "Dev Server",
            27017: "MongoDB",
            6379: "Redis",
            11211: "Memcached",
            5672: "AMQP",
            5601: "Kibana",
            9200: "Elasticsearch",
            9300: "Elasticsearch",
            514: "Syslog",
            123: "NTP",
            67: "DHCP Server",
            68: "DHCP Client",
            88: "Kerberos",
            464: "Kerberos Change",
            49: "TACACS",
            1812: "RADIUS",
            1813: "RADIUS Accounting"
        }
        
        # Common port categories
        port_categories = {
            "web": [80, 443, 8080, 8443, 8000, 8888],
            "mail": [25, 110, 143, 465, 587, 993, 995],
            "file_transfer": [20, 21, 22, 445, 139, 138, 137],
            "database": [1433, 3306, 5432, 27017, 6379, 11211],
            "remote_access": [22, 23, 3389, 5900],
            "voip": [5060, 5061, 10000, 20000],
            "dns": [53, 853],
            "monitoring": [161, 162, 199, 4000],
            "directory_services": [389, 636, 88, 464],
            "infrastructure": [123, 514, 67, 68]
        }

        for prefix in ["src", "dst"]:
            port_field = f"{prefix}_port"
            port = log_data.get(port_field)
            
            if port is not None:
                try:
                    # Ensure port is treated as integer
                    port = int(port)
                    port_info[port_field] = port
                    
                    # Add service name if it's a well-known port
                    port_info[f"{prefix}_service"] = well_known_ports.get(port, "Unknown")
                    
                    # Add port category
                    for category, ports in port_categories.items():
                        if port in ports:
                            port_info[f"{prefix}_port_category"] = category
                            break
                    else:
                        # Check port ranges for categorization
                        if 0 <= port <= 1023:
                            port_info[f"{prefix}_port_category"] = "system"
                        elif 1024 <= port <= 49151:
                            port_info[f"{prefix}_port_category"] = "registered"
                        else:
                            port_info[f"{prefix}_port_category"] = "dynamic"
                            
                except (ValueError, TypeError):
                    # If it's not a valid integer port, log and store as is
                    self.logger.debug(f"Invalid port format: {port}")
                    port_info[port_field] = port
        
        return port_info

    def normalize_action(self, action: str) -> str:
        """Normalize firewall action to a standard set (allow, block, drop, reject, etc.)

        Args:
            action: The action string from the firewall log

        Returns:
            Normalized action string
        """
        action = action.lower()
        
        # Map various action terms to normalized values
        if action in ["accept", "pass", "permitted", "built", "allow"]:
            return "allow"
        elif action in ["drop", "deny", "denied", "block", "rejected"]:
            return "block"
        elif action in ["reject"]:
            return "reject"
        elif action in ["teardown", "closed", "disconnect"]:
            return "disconnect"
        elif action in ["nat", "translated", "snat", "dnat"]:
            return "nat"
        elif action in ["info", "log", "notice"]:
            return "info"
        else:
            return action  # Keep original if no mapping found

    def get_log_level_from_action(self, action: str) -> str:
        """Determine log level based on firewall action

        Args:
            action: Normalized action string

        Returns:
            Log level string
        """
        # Map actions to log levels
        action_to_level = {
            "allow": "INFO",
            "block": "WARNING",
            "reject": "WARNING", 
            "disconnect": "INFO",
            "nat": "INFO",
            "info": "INFO",
            # Default for unknown actions
            "default": "INFO"
        }
        
        return action_to_level.get(action, action_to_level["default"])

    def extract_protocol(self, protocol: str) -> Dict[str, Any]:
        """Extract and categorize protocol information

        Args:
            protocol: Protocol string or number from log

        Returns:
            Dictionary with protocol information
        """
        protocol_info = {}
        
        # Protocol number to name mapping (common ones)
        protocol_map = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "47": "GRE",
            "50": "ESP",
            "51": "AH",
            "58": "ICMPv6",
            "89": "OSPF",
            "132": "SCTP"
        }
        
        # Try to normalize protocol value
        if protocol.isdigit():
            protocol_info["protocol_number"] = int(protocol)
            protocol_info["protocol_name"] = protocol_map.get(protocol, f"PROTO:{protocol}")
        else:
            protocol_upper = protocol.upper()
            protocol_info["protocol_name"] = protocol_upper
            
            # Try to find protocol number for known protocols
            for num, name in protocol_map.items():
                if name == protocol_upper:
                    protocol_info["protocol_number"] = int(num)
                    break
        
        return protocol_info

    def create_log_entry(
        self, 
        timestamp: datetime,
        message: str,
        parsed_data: Dict[str, Any],
        raw_data: str
    ) -> LogEntry:
        """Create a standardized LogEntry from parsed firewall log data

        Args:
            timestamp: Log timestamp
            message: Log message summary
            parsed_data: Dictionary of parsed log data
            raw_data: Original raw log line

        Returns:
            LogEntry object
        """
        # Get normalized action
        action = parsed_data.get("action", "unknown")
        normalized_action = self.normalize_action(action)
        
        # Determine log level based on action
        level = self.get_log_level_from_action(normalized_action)
        
        # Create metadata
        metadata = {
            "log_type": "firewall",
            "firewall_type": self.name,
            "action": normalized_action,
            "connection_type": parsed_data.get("connection_type", "unknown"),
            "protocol": parsed_data.get("protocol", "unknown"),
            "rule_id": parsed_data.get("rule_id"),
            "interface_in": parsed_data.get("interface_in"),
            "interface_out": parsed_data.get("interface_out")
        }
        
        # Remove None values
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        try:
            self.logger.debug(f"Creating log entry: {message}")
            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=self.name,
                raw_data=raw_data,
                parsed_data=parsed_data,
                metadata=metadata
            )
        except Exception as e:
            self.logger.error(f"Error creating log entry: {str(e)}")
            raise ParserError(f"Error creating log entry: {str(e)}")

    def parse_timestamp(self, timestamp_str: str, year: Optional[int] = None) -> datetime:
        """Parse timestamp with various formats commonly found in firewall logs

        Args:
            timestamp_str: Timestamp string to parse
            year: Optional year to use if not in timestamp

        Returns:
            Parsed datetime object

        Raises:
            ValueError: If timestamp cannot be parsed
        """
        formats = [
            # Common timestamp formats in firewall logs
            "%Y-%m-%d %H:%M:%S",  # 2023-05-23 14:47:34
            "%b %d %H:%M:%S",      # May 23 14:24:55
            "%b %d %Y %H:%M:%S",   # May 23 2023 14:24:55
            "%d/%b/%Y:%H:%M:%S",   # 23/May/2023:14:24:55
            "%Y/%m/%d %H:%M:%S",   # 2023/05/23 14:24:55
            "%d-%b-%Y %H:%M:%S",   # 23-May-2023 14:24:55
            "%m/%d/%Y %H:%M:%S",   # 05/23/2023 14:24:55
            "%d/%m/%Y %H:%M:%S",   # 23/05/2023 14:24:55
            "%H:%M:%S %b %d %Y",   # 14:24:55 May 23 2023
        ]
        
        # Try all formats
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                
                # If format doesn't include year, use current or provided year
                if "%Y" not in fmt and "%y" not in fmt:
                    current_year = year or datetime.now().year
                    dt = dt.replace(year=current_year)
                
                return dt
            except ValueError:
                continue
        
        # If all formats fail, try with some additional processing
        try:
            # Some logs have timestamps with timezone info
            import dateutil.parser
            return dateutil.parser.parse(timestamp_str)
        except:
            self.logger.warning(f"Unable to parse timestamp: {timestamp_str}")
            raise ValueError(f"Unable to parse timestamp: {timestamp_str}")
            
    def extract_common_firewall_fields(self, line: str) -> Dict[str, Any]:
        """Extract common firewall fields from a log line using regex
        
        Args:
            line: Raw log line
            
        Returns:
            Dictionary with extracted fields
        """
        # Common patterns in firewall logs
        patterns = {
            "src": r"(?:SRC=|src=|source=|from=)([^ ]+)",
            "dst": r"(?:DST=|dst=|destination=|to=)([^ ]+)",
            "src_port": r"(?:SPT=|sport=|src[_\-]port=)(\d+)",
            "dst_port": r"(?:DPT=|dport=|dst[_\-]port=)(\d+)",
            "protocol": r"(?:PROTO=|proto=|protocol=)([^ ]+)",
            "interface_in": r"(?:IN=|in=|intf_in=|input=|iface_in=)([^ ]+)",
            "interface_out": r"(?:OUT=|out=|intf_out=|output=|iface_out=)([^ ]+)",
            "action": r"(?:action=|RULE=|ACTION=|DISPOSITION=)([^ ]+)",
            "rule_id": r"(?:rule_id=|RULE[_\-]ID=|rule=|id=)([^ ]+)"
        }
        
        result = {}
        
        # Extract fields using regex
        for field, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                result[field] = match.group(1)
                
        # Try to determine the action from common keywords if not explicitly found
        if "action" not in result:
            if any(keyword in line.upper() for keyword in ["BLOCK", "DROP", "DENY", "REJECT"]):
                result["action"] = "block"
            elif any(keyword in line.upper() for keyword in ["ACCEPT", "ALLOW", "PASS", "PERMIT"]):
                result["action"] = "allow"
        
        return result