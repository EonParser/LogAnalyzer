import re
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple

from ..firewall_base import FirewallLogParser
from ...parsers.base import LogEntry, ParserError


class CiscoASALogParser(FirewallLogParser):
    """Parser for Cisco ASA firewall logs"""

    # Example log format:
    # May 23 14:24:55 %ASA-6-302013: Built inbound TCP connection 53982 for outside:203.0.113.100/35663 (203.0.113.100/35663) to inside:10.1.1.100/80 (172.16.1.100/80)

    # ASA Message format
    ASA_MESSAGE_PATTERN = r"%ASA-(\d)-(\d+): (.+)"
    
    # Timestamp patterns
    TIMESTAMP_PATTERN = r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    
    # Common ASA message types
    ASA_MESSAGE_TYPES = {
        # Connection events
        "302013": {"desc": "Built outbound connection", "action": "allow"},
        "302014": {"desc": "Teardown outbound connection", "action": "disconnect"},
        "302015": {"desc": "Built inbound connection", "action": "allow"},
        "302016": {"desc": "Teardown inbound connection", "action": "disconnect"},
        "302020": {"desc": "Built outbound ICMP connection", "action": "allow"},
        "302021": {"desc": "Teardown outbound ICMP connection", "action": "disconnect"},
        
        # Denied connections
        "106001": {"desc": "Inbound access denied", "action": "block"},
        "106002": {"desc": "Outbound access denied", "action": "block"},
        "106006": {"desc": "Denied inbound UDP", "action": "block"},
        "106007": {"desc": "Denied inbound UDP", "action": "block"},
        "106010": {"desc": "Denied inbound ICMP", "action": "block"},
        "106011": {"desc": "Denied inbound ICMP", "action": "block"},
        "106015": {"desc": "Denied TCP", "action": "block"},
        "106016": {"desc": "Denied IP spoof", "action": "block"},
        "106017": {"desc": "Denied outbound duplicate TCP", "action": "block"},
        "106018": {"desc": "Denied inbound duplicate TCP", "action": "block"},
        "106023": {"desc": "Denied by ACL", "action": "block"},
        "106027": {"desc": "Denied inbound ICMP", "action": "block"},
        
        # NAT events
        "305009": {"desc": "NAT translation creation", "action": "nat"},
        "305010": {"desc": "NAT translation teardown", "action": "disconnect"},
        "305011": {"desc": "NAT translation overflow", "action": "info"},
        "305012": {"desc": "NAT translation teardown", "action": "disconnect"},
        
        # Miscellaneous
        "106100": {"desc": "Access list hit", "action": "info"},
        "111010": {"desc": "User authentication", "action": "info"},
        "113019": {"desc": "Syslog dropped", "action": "info"},
        "710003": {"desc": "TCP connection limit", "action": "block"},
        "713172": {"desc": "VPN connection failed", "action": "block"},
    }
    
    def __init__(self):
        """Initialize Cisco ASA log parser"""
        super().__init__()
        self.name = "cisco_asa"
        self.description = "Cisco ASA Firewall Log Parser"
        
        # Compile regex patterns
        self.timestamp_regex = re.compile(self.TIMESTAMP_PATTERN)
        self.asa_message_regex = re.compile(self.ASA_MESSAGE_PATTERN)

    def supports_format(self, line: str) -> bool:
        """Check if line matches Cisco ASA log format"""
        # Check for key Cisco ASA indicators
        return "%ASA-" in line

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse Cisco ASA log line into structured data

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if successful, None if line should be skipped

        Raises:
            ParserError: If line cannot be parsed
        """
        try:
            line = line.strip()
            if not line:
                return None
                
            # Extract timestamp
            timestamp_match = self.timestamp_regex.search(line)
            if not timestamp_match:
                # No timestamp found, use current time
                timestamp = datetime.now()
            else:
                # Parse standard timestamp
                timestamp_str = timestamp_match.group(1)
                try:
                    timestamp = self.parse_timestamp(timestamp_str)
                except ValueError:
                    timestamp = datetime.now()
            
            # Extract ASA message parts
            asa_match = self.asa_message_regex.search(line)
            if not asa_match:
                # Not an ASA log we can parse
                return None
                
            severity = asa_match.group(1)
            message_id = asa_match.group(2)
            message_text = asa_match.group(3)
            
            # Start building data structure
            data = {
                "severity": severity,
                "message_id": message_id,
                "message_text": message_text
            }
            
            # Set action and description based on message ID
            message_info = self.ASA_MESSAGE_TYPES.get(message_id, {"desc": "Unknown", "action": "info"})
            data["action"] = message_info["action"]
            data["description"] = message_info["desc"]
            
            # Parse based on message type
            if message_id in ["302013", "302015"]:  # Built connection
                return self._parse_connection_built(message_text, timestamp, data, line)
            elif message_id in ["302014", "302016"]:  # Teardown connection
                return self._parse_connection_teardown(message_text, timestamp, data, line)
            elif message_id.startswith("106"):  # Denied connection
                return self._parse_connection_denied(message_text, timestamp, data, line)
            else:
                # Generic parsing for other message types
                return self._parse_generic_asa(message_text, timestamp, data, line)
                
        except Exception as e:
            raise ParserError(f"Error parsing Cisco ASA log: {str(e)}")
    
    def _parse_connection_built(self, message_text: str, timestamp: datetime, 
                               data: Dict[str, Any], raw_line: str) -> Optional[LogEntry]:
        """Parse ASA connection built message
        
        Args:
            message_text: The message part of the log
            timestamp: Log timestamp
            data: Partially parsed data
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        # Pattern for built connection messages
        # Built inbound TCP connection 53982 for outside:203.0.113.100/35663 (203.0.113.100/35663) to inside:10.1.1.100/80 (172.16.1.100/80)
        pattern = r"Built (inbound|outbound) (\w+) connection (\d+) for (\w+):([^/]+)/(\d+) \(([^)]+)\) to (\w+):([^/]+)/(\d+) \(([^)]+)\)"
        match = re.search(pattern, message_text)
        
        if match:
            direction = match.group(1)  # inbound or outbound
            protocol = match.group(2)   # TCP, UDP, etc.
            conn_id = match.group(3)    # Connection ID
            src_interface = match.group(4)  # Source interface
            src_ip = match.group(5)     # Source IP
            src_port = match.group(6)   # Source port
            src_translated = match.group(7)  # Translated source
            dst_interface = match.group(8)  # Destination interface
            dst_ip = match.group(9)     # Destination IP
            dst_port = match.group(10)  # Destination port
            dst_translated = match.group(11)  # Translated destination
            
            # Add to data dictionary
            data.update({
                "direction": direction,
                "protocol": protocol,
                "connection_id": conn_id,
                "interface_in": src_interface if direction == "inbound" else dst_interface,
                "interface_out": dst_interface if direction == "inbound" else src_interface,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "src_translated": src_translated,
                "dst_translated": dst_translated,
                "connection_type": "initial"
            })
            
            # Extract IP information
            ip_info = self.extract_ips(data)
            data.update(ip_info)
            
            # Extract port information
            port_info = self.extract_ports(data)
            data.update(port_info)
            
            # Extract protocol information
            protocol_info = self.extract_protocol(protocol)
            data.update(protocol_info)
            
            # Create message summary
            protocol_name = data.get("protocol_name", protocol).upper()
            message = f"{data['action'].upper()} {protocol_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({direction})"
            
            # Add connection ID
            message += f" [Connection:{conn_id}]"
            
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=raw_line
            )
            
        return None
    
    def _parse_connection_teardown(self, message_text: str, timestamp: datetime, 
                                  data: Dict[str, Any], raw_line: str) -> Optional[LogEntry]:
        """Parse ASA connection teardown message
        
        Args:
            message_text: The message part of the log
            timestamp: Log timestamp
            data: Partially parsed data
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        # Pattern for teardown connection messages
        # Teardown TCP connection 53982 for outside:203.0.113.100/35663 to inside:10.1.1.100/80 duration 0:00:00 bytes 0 reason normal
        pattern = r"Teardown (\w+) connection (\d+) for (\w+):([^/]+)/(\d+) to (\w+):([^/]+)/(\d+) duration ([^ ]+) bytes (\d+) (.+)"
        match = re.search(pattern, message_text)
        
        if match:
            protocol = match.group(1)   # TCP, UDP, etc.
            conn_id = match.group(2)    # Connection ID
            src_interface = match.group(3)  # Source interface
            src_ip = match.group(4)     # Source IP
            src_port = match.group(5)   # Source port
            dst_interface = match.group(6)  # Destination interface
            dst_ip = match.group(7)     # Destination IP
            dst_port = match.group(8)   # Destination port
            duration = match.group(9)   # Duration
            bytes_count = match.group(10)  # Bytes transferred
            reason = match.group(11)    # Reason for teardown
            
            # Add to data dictionary
            data.update({
                "protocol": protocol,
                "connection_id": conn_id,
                "interface_in": src_interface,
                "interface_out": dst_interface,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "duration": duration,
                "bytes": bytes_count,
                "reason": reason,
                "connection_type": "teardown"
            })
            
            # Extract IP information
            ip_info = self.extract_ips(data)
            data.update(ip_info)
            
            # Extract port information
            port_info = self.extract_ports(data)
            data.update(port_info)
            
            # Extract protocol information
            protocol_info = self.extract_protocol(protocol)
            data.update(protocol_info)
            
            # Create message summary
            protocol_name = data.get("protocol_name", protocol).upper()
            message = f"DISCONNECT {protocol_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            # Add connection ID and reason
            message += f" [Connection:{conn_id}] [{reason}]"
            
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=raw_line
            )
            
        return None
    
    def _parse_connection_denied(self, message_text: str, timestamp: datetime, 
                               data: Dict[str, Any], raw_line: str) -> Optional[LogEntry]:
        """Parse ASA connection denied message
        
        Args:
            message_text: The message part of the log
            timestamp: Log timestamp
            data: Partially parsed data
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        # Different patterns for denied messages
        
        # Pattern 1: Denied by ACL
        # Denied protocol src interface_name:src_ip/src_port dst interface_name:dst_ip/dst_port by access-group "acl_name"
        pattern1 = r"Denied (\w+) (\w+) ([^:]+):([^/]+)/(\d+) (\w+) ([^:]+):([^/]+)/(\d+) by access-group \"([^\"]+)\""
        match = re.search(pattern1, message_text)
        
        if match:
            protocol = match.group(1)
            src_interface = match.group(2)
            src_ip = match.group(4)
            src_port = match.group(5)
            dst_interface = match.group(6)
            dst_ip = match.group(8)
            dst_port = match.group(9)
            acl_name = match.group(10)
            
            # Add to data dictionary
            data.update({
                "protocol": protocol,
                "interface_in": src_interface,
                "interface_out": dst_interface,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "acl_name": acl_name,
                "reason": f"Denied by ACL {acl_name}"
            })
        else:
            # Pattern 2: Simple denied message
            # Denied inbound ICMP from 10.1.1.100 to 10.1.1.1 on interface inside
            pattern2 = r"Denied (\w+) (\w+) from ([^ ]+) to ([^ ]+)(?: on interface ([^ ]+))?"
            match = re.search(pattern2, message_text)
            
            if match:
                direction = match.group(1)  # inbound or outbound
                protocol = match.group(2)   # ICMP, UDP, etc.
                src_ip = match.group(3)     # Source IP
                dst_ip = match.group(4)     # Destination IP
                interface = match.group(5)  # Interface (optional)
                
                # Add to data dictionary
                data.update({
                    "direction": direction,
                    "protocol": protocol,
                    "src": src_ip,
                    "dst": dst_ip
                })
                
                if interface:
                    if direction == "inbound":
                        data["interface_in"] = interface
                    else:
                        data["interface_out"] = interface
            else:
                # Try to extract basic IP information from message
                ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
                ips = re.findall(ip_pattern, message_text)
                
                if len(ips) >= 2:
                    data.update({
                        "src": ips[0],
                        "dst": ips[1]
                    })
                    
                # Try to extract protocol
                proto_pattern = r"(\bTCP\b|\bUDP\b|\bICMP\b|\bIP\b)"
                proto_match = re.search(proto_pattern, message_text, re.IGNORECASE)
                if proto_match:
                    data["protocol"] = proto_match.group(1).upper()
                
        # If we have source and destination IPs, create a log entry
        if "src" in data and "dst" in data:
            # Extract IP information
            ip_info = self.extract_ips(data)
            data.update(ip_info)
            
            # Extract port information
            if "src_port" in data and "dst_port" in data:
                port_info = self.extract_ports(data)
                data.update(port_info)
            
            # Extract protocol information
            if "protocol" in data:
                protocol_info = self.extract_protocol(data["protocol"])
                data.update(protocol_info)
            
            # Create message summary
            protocol_str = data.get("protocol_name", data.get("protocol", "unknown")).upper()
            src_ip = data.get("src", "unknown")
            dst_ip = data.get("dst", "unknown")
            src_port = f":{data.get('src_port', '')}" if "src_port" in data else ""
            dst_port = f":{data.get('dst_port', '')}" if "dst_port" in data else ""
            
            message = f"BLOCK {protocol_str} {src_ip}{src_port} -> {dst_ip}{dst_port}"
            
            # Add reason if available
            if "reason" in data:
                message += f" [{data['reason']}]"
                
            # Add ACL name if available
            if "acl_name" in data:
                message += f" [ACL:{data['acl_name']}]"
                
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=raw_line
            )
            
        return None
    
    def _parse_generic_asa(self, message_text: str, timestamp: datetime, 
                          data: Dict[str, Any], raw_line: str) -> Optional[LogEntry]:
        """Parse generic ASA message
        
        Args:
            message_text: The message part of the log
            timestamp: Log timestamp
            data: Partially parsed data
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        # Try to extract IPs from the message
        ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
        ips = re.findall(ip_pattern, message_text)
        
        if len(ips) >= 2:
            # Assume first two IPs are source and destination
            data["src"] = ips[0]
            data["dst"] = ips[1]
            
            # Extract IP information
            ip_info = self.extract_ips(data)
            data.update(ip_info)
        
        # Try to extract protocol information
        proto_pattern = r"(\bTCP\b|\bUDP\b|\bICMP\b|\bGRE\b|\bESP\b|\bAH\b|\bIP\b)"
        proto_match = re.search(proto_pattern, message_text, re.IGNORECASE)
        if proto_match:
            protocol = proto_match.group(1).upper()
            data["protocol"] = protocol
            
            # Extract protocol information
            protocol_info = self.extract_protocol(protocol)
            data.update(protocol_info)
        
        # Try to extract ports
        port_pattern = r"\/(\d+)"
        ports = re.findall(port_pattern, message_text)
        
        if len(ports) >= 2:
            data["src_port"] = ports[0]
            data["dst_port"] = ports[1]
            
            # Extract port information
            port_info = self.extract_ports(data)
            data.update(port_info)
        
        # Create message summary based on available information
        action = data.get("action", "unknown").upper()
        message_id = data.get("message_id", "")
        description = data.get("description", "")
        
        if "src" in data and "dst" in data:
            protocol_str = data.get("protocol_name", data.get("protocol", "unknown")).upper()
            src_ip = data.get("src", "unknown")
            dst_ip = data.get("dst", "unknown")
            src_port = f":{data.get('src_port', '')}" if "src_port" in data else ""
            dst_port = f":{data.get('dst_port', '')}" if "dst_port" in data else ""
            
            message = f"{action} {protocol_str} {src_ip}{src_port} -> {dst_ip}{dst_port}"
        else:
            # Use the message ID and description if IP addresses are not available
            message = f"{action} {message_id} {description}"
            
        # Add additional context from the message text
        message += f" [{message_text[:50]}...]" if len(message_text) > 50 else f" [{message_text}]"
        
        # Create log entry
        return self.create_log_entry(
            timestamp=timestamp,
            message=message,
            parsed_data=data,
            raw_data=raw_line
        )