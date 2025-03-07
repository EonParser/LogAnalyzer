import re
from datetime import datetime
from typing import Dict, Optional, Any, List

from ..firewall_base import FirewallLogParser
from ...parsers.base import LogEntry, ParserError


class PFSenseLogParser(FirewallLogParser):
    """Parser for pfSense firewall logs"""

    # Example log format (filterlog):
    # Jan 23 20:13:50 pfSense filterlog: 100001,16,match,block,in,4,0x0,,64,6,0,0,DF,17,0,16406,443,0,S,3626212638,,60,,

    # Timestamp patterns
    TIMESTAMP_PATTERN = r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    
    # Hostname and process
    HOSTNAME_PROCESS_PATTERN = r"(?:\s+([^\s]+)\s+([^\s]+):)"
    
    # pfSense filterlog format (CSV fields after 'filterlog:')
    FILTERLOG_PREFIX = r"filterlog:"
    
    def __init__(self):
        """Initialize pfSense log parser"""
        super().__init__()
        self.name = "pfsense"
        self.description = "pfSense Firewall Log Parser"
        
        # Compile regex patterns
        self.timestamp_regex = re.compile(self.TIMESTAMP_PATTERN)
        self.hostname_process_regex = re.compile(self.HOSTNAME_PROCESS_PATTERN)
        
        # Define field maps for the filterlog CSV format
        self.filterlog_ipv4_fields = [
            "rule_id",            # 0: Rule number
            "sub_rule_id",        # 1: Subrule number
            "anchor",             # 2: Anchor
            "tracker",            # 3: Tracker ID
            "interface",          # 4: Interface name
            "reason",             # 5: Reason
            "action",             # 6: Action (pass, block, etc.)
            "direction",          # 7: Direction (in, out)
            "ip_version",         # 8: IP version (4, 6)
            "tos",                # 9: TOS
            "ecn",                # 10: ECN
            "ttl",                # 11: TTL
            "id",                 # 12: ID
            "offset",             # 13: Offset
            "flags",              # 14: Flags
            "protocol_id",        # 15: Protocol ID
            "protocol",           # 16: Protocol name
            "length",             # 17: Length
            "src",                # 18: Source IP
            "dst",                # 19: Destination IP
            "src_port",           # 20: Source port (for TCP/UDP)
            "dst_port",           # 21: Destination port (for TCP/UDP)
            "data_length",        # 22: Data length
            "tcp_flags",          # 23: TCP flags
            "sequence",           # 24: Sequence number
            "ack",                # 25: ACK number
            "window",             # 26: Window
            "urg",                # 27: URG
            "options"             # 28: Options
        ]
        
        self.filterlog_ipv6_fields = [
            "rule_id",            # 0: Rule number
            "sub_rule_id",        # 1: Subrule number
            "anchor",             # 2: Anchor
            "tracker",            # 3: Tracker ID
            "interface",          # 4: Interface name
            "reason",             # 5: Reason
            "action",             # 6: Action (pass, block, etc.)
            "direction",          # 7: Direction (in, out)
            "ip_version",         # 8: IP version (4, 6)
            "class",              # 9: Class
            "flow_label",         # 10: Flow label
            "hop_limit",          # 11: Hop limit
            "protocol",           # 12: Protocol
            "protocol_id",        # 13: Protocol ID
            "length",             # 14: Length
            "src",                # 15: Source IP
            "dst",                # 16: Destination IP
            "src_port",           # 17: Source port (for TCP/UDP)
            "dst_port",           # 18: Destination port (for TCP/UDP)
            "data_length",        # 19: Data length
            "tcp_flags",          # 20: TCP flags
            "sequence",           # 21: Sequence number
            "ack",                # 22: ACK number
            "window",             # 23: Window
            "urg",                # 24: URG
            "options"             # 25: Options
        ]

    def supports_format(self, line: str) -> bool:
        """Check if line matches pfSense log format"""
        # Check for key pfSense indicators
        return "filterlog:" in line or "pf:" in line or "pfSense" in line

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse pfSense log line into structured data

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
            
            # Extract hostname and process
            hostname = None
            process = None
            hostname_match = self.hostname_process_regex.search(line)
            if hostname_match:
                hostname = hostname_match.group(1)
                process = hostname_match.group(2)
            
            # Check if this is a filterlog entry (most common pfSense format)
            if "filterlog:" in line:
                # Extract the CSV part after "filterlog:"
                csv_part = line.split("filterlog:", 1)[1].strip()
                return self._parse_filterlog(csv_part, timestamp, line)
            
            # If not filterlog, check for other pfSense formats
            if "pf:" in line:
                return self._parse_pf_log(line, timestamp)
                
            # Last resort - try to parse as generic pfSense log
            return self._parse_generic_pfsense(line, timestamp)
            
        except Exception as e:
            raise ParserError(f"Error parsing pfSense log: {str(e)}")
    
    def _parse_filterlog(self, csv_part: str, timestamp: datetime, raw_line: str) -> Optional[LogEntry]:
        """Parse pfSense filterlog format
        
        Args:
            csv_part: CSV part of the filterlog entry
            timestamp: Log timestamp
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if data is invalid
        """
        # Split CSV fields, handling commas within quoted values
        fields = []
        current_field = ""
        in_quotes = False
        
        for char in csv_part:
            if char == ',' and not in_quotes:
                fields.append(current_field)
                current_field = ""
            elif char == '"':
                in_quotes = not in_quotes
                current_field += char
            else:
                current_field += char
                
        # Add the last field
        fields.append(current_field)
        
        # Make sure we have enough fields
        if len(fields) < 10:
            # Not enough fields for valid filterlog
            return None
            
        # Determine if IPv4 or IPv6 based on field 8
        is_ipv6 = False
        try:
            ip_version = int(fields[8])
            is_ipv6 = (ip_version == 6)
        except (ValueError, IndexError):
            # Default to IPv4 if we can't determine
            is_ipv6 = False
            
        # Map fields to keys
        field_map = self.filterlog_ipv6_fields if is_ipv6 else self.filterlog_ipv4_fields
        data = {}
        
        # Parse fields based on the map
        for i, field_name in enumerate(field_map):
            if i < len(fields):
                # Skip empty fields and replace with None
                if fields[i] and fields[i] != '""':
                    data[field_name] = fields[i].strip('"')
                else:
                    data[field_name] = None
        
        # Set interface_in/out based on direction
        if "direction" in data and "interface" in data:
            if data["direction"] == "in":
                data["interface_in"] = data["interface"]
            elif data["direction"] == "out":
                data["interface_out"] = data["interface"]
        
        # Normalize action field
        if "action" in data:
            data["action"] = self.normalize_action(data["action"])
        
        # Extract IP information
        ip_info = self.extract_ips(data)
        data.update(ip_info)
        
        # Extract port information
        port_info = self.extract_ports(data)
        data.update(port_info)
        
        # Extract protocol information
        if "protocol" in data:
            protocol_info = self.extract_protocol(data["protocol"])
            data.update(protocol_info)
            
        # Create message summary
        action = data.get("action", "unknown")
        protocol_str = data.get("protocol_name", data.get("protocol", "unknown")).upper()
        src_ip = data.get("src", "unknown")
        dst_ip = data.get("dst", "unknown")
        src_port = f":{data.get('src_port', '')}" if "src_port" in data and data["src_port"] else ""
        dst_port = f":{data.get('dst_port', '')}" if "dst_port" in data and data["dst_port"] else ""
        
        message = f"{action.upper()} {protocol_str} {src_ip}{src_port} -> {dst_ip}{dst_port}"
        
        # Add interface and direction
        interface = data.get("interface", "")
        direction = data.get("direction", "")
        if interface and direction:
            message += f" ({direction}:{interface})"
            
        # Add rule ID if available
        rule_id = data.get("rule_id")
        if rule_id:
            message += f" [Rule:{rule_id}]"
            
        # Add reason if available
        reason = data.get("reason")
        if reason:
            message += f" [{reason}]"
        
        # Create log entry
        return self.create_log_entry(
            timestamp=timestamp,
            message=message,
            parsed_data=data,
            raw_data=raw_line
        )
    
    def _parse_generic_pfsense(self, line: str, timestamp: datetime) -> Optional[LogEntry]:
        """Parse generic pfSense log (non-filterlog)
        
        Args:
            line: Raw log line
            timestamp: Log timestamp
            
        Returns:
            LogEntry if successful, None if data is invalid
        """
        # Try to extract key elements from the log line
        data = {}
        
        # Extract IP addresses
        src_match = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', line)
        if src_match:
            data["src"] = src_match.group(1)
            
        dst_match = re.search(r'dst\s+(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', line)
        if dst_match:
            data["dst"] = dst_match.group(1)
            
        # Extract ports
        src_port_match = re.search(r'sport\s+(\d+)', line)
        if src_port_match:
            data["src_port"] = src_port_match.group(1)
            
        dst_port_match = re.search(r'dport\s+(\d+)', line)
        if dst_port_match:
            data["dst_port"] = dst_port_match.group(1)
            
        # Extract protocol
        proto_match = re.search(r'proto\s+(\w+)', line)
        if proto_match:
            data["protocol"] = proto_match.group(1)
            
        # Extract action
        action = "unknown"
        if "block" in line.lower():
            action = "block"
        elif "pass" in line.lower():
            action = "allow"
        elif "match" in line.lower():
            action = "match"
            
        data["action"] = action
        
        # Extract rule ID if present
        rule_match = re.search(r'rule\s+(\d+)', line)
        if rule_match:
            data["rule_id"] = rule_match.group(1)
            
        # Extract interface
        iface_match = re.search(r'on\s+(\w+)', line)
        if iface_match:
            data["interface"] = iface_match.group(1)
            
        # If we have minimal data, create a log entry
        if "src" in data or "dst" in data:
            # Extract IP information
            ip_info = self.extract_ips(data)
            data.update(ip_info)
            
            # Extract port information
            port_info = self.extract_ports(data)
            data.update(port_info)
            
            # Extract protocol information
            if "protocol" in data:
                protocol_info = self.extract_protocol(data["protocol"])
                data.update(protocol_info)
                
            # Create message summary using available data
            protocol_str = data.get("protocol_name", data.get("protocol", "unknown")).upper()
            src_ip = data.get("src", "unknown")
            dst_ip = data.get("dst", "unknown")
            src_port = f":{data.get('src_port', '')}" if "src_port" in data else ""
            dst_port = f":{data.get('dst_port', '')}" if "dst_port" in data else ""
            
            message = f"{action.upper()} {protocol_str} {src_ip}{src_port} -> {dst_ip}{dst_port}"
            
            # Add interface if available
            interface = data.get("interface")
            if interface:
                message += f" (interface:{interface})"
                
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=line
            )
        
        return None