import re
from datetime import datetime
from typing import Dict, Optional, Any

from ..firewall_base import FirewallLogParser
from ..base import LogEntry, ParserError


class IPTablesLogParser(FirewallLogParser):
    """Parser for iptables firewall logs"""

    # Example log format:
    # Feb 23 11:12:56 firewall kernel: [14395.156933] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:00:11:22:33:44:55:08:00 SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=38815 DF PROTO=TCP SPT=48619 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0

    # This regex handles both syslog-style timestamps and kernel timestamps
    TIMESTAMP_PATTERN = r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    
    # Kernel bracket timestamp is optional
    KERNEL_TIMESTAMP_PATTERN = r"(?:\[\s*(\d+\.\d+)\s*\])?"
    
    # Match hostname and process (typically 'kernel:')
    HOSTNAME_PATTERN = r"(?:\s+([^\s]+)\s+([^\s]+):)?"
    
    # Prefixes sometimes added by syslog or custom iptables logging
    PREFIX_PATTERN = r"(?:\s*(?:IN=|iptables|firewall|netfilter|kernel:)|\s*\[[^\]]+\]\s*)?"
    
    # Main log data pattern - key-value pairs
    IPTABLES_PATTERN = r"(?:IN=([^\s]*)\s+)?(?:OUT=([^\s]*)\s+)?(?:MAC=([^\s]*)\s+)?(?:SRC=([^\s]*)\s+)?(?:DST=([^\s]*)\s+)?(?:LEN=(\d+)\s+)?(?:TOS=(0x[^\s]*)\s+)?(?:PREC=(0x[^\s]*)\s+)?(?:TTL=(\d+)\s+)?(?:ID=(\d+)\s+)?((?:(?:CE|DF|MF)\s+)*)(?:PROTO=([^\s]*)\s+)?(?:SPT=(\d+)\s+)?(?:DPT=(\d+)\s+)?(?:WINDOW=(\d+)\s+)?(?:RES=(0x[^\s]*)\s+)?(?:(?:(?:ACK|FIN|SYN|RST|PSH|URG)\s+)*)?(?:URGP=(\d+))?"

    # This will be set to the specific iptables format being parsed
    custom_prefix = None
    
    def __init__(self):
        """Initialize iptables log parser"""
        super().__init__()
        self.name = "iptables"
        self.description = "IPTables Firewall Log Parser"
        
        # Compile regex patterns
        self.timestamp_regex = re.compile(self.TIMESTAMP_PATTERN)
        self.kernel_timestamp_regex = re.compile(self.KERNEL_TIMESTAMP_PATTERN)
        self.iptables_regex = re.compile(self.IPTABLES_PATTERN)

    def supports_format(self, line: str) -> bool:
        """Check if line matches iptables log format"""
        # Check for key iptables indicators
        iptables_indicators = ["IN=", "OUT=", "SRC=", "DST=", "PROTO="]
        
        # Line should contain at least 3 of these indicators to be considered iptables format
        indicator_count = sum(1 for indicator in iptables_indicators if indicator in line)
        
        # Also require some basic iptables fields
        has_proto = "PROTO=" in line
        has_src_or_dst = "SRC=" in line or "DST=" in line
        
        return indicator_count >= 3 and (has_proto or has_src_or_dst)

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse iptables log line into structured data

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
                # If no standard timestamp, try to find the kernel timestamp
                # But we'll need to use current date as it only has seconds since boot
                kernel_match = self.kernel_timestamp_regex.search(line)
                if kernel_match:
                    # Use current date/time since kernel timestamp is just seconds since boot
                    timestamp = datetime.now()
                else:
                    # No timestamp found, use current time
                    timestamp = datetime.now()
            else:
                # Parse standard timestamp
                timestamp_str = timestamp_match.group(1)
                try:
                    timestamp = self.parse_timestamp(timestamp_str)
                except ValueError:
                    timestamp = datetime.now()
            
            # Find where the actual iptables data starts
            if timestamp_match:
                data_start = timestamp_match.end()
            else:
                data_start = 0
                
            # Check for hostname and process if present
            hostname = None
            process = None
            
            # Try to detect and store custom prefix for future pattern matching
            if not self.custom_prefix:
                # Look for standard prefixes like "kernel:", "iptables:", etc.
                prefix_match = re.search(r'\s+([^\s]+)\s+([^\s]+):', line)
                if prefix_match:
                    hostname = prefix_match.group(1)
                    process = prefix_match.group(2)
                    
                    # Store this prefix for future matches
                    self.custom_prefix = f"{hostname} {process}:"
            
            # Extract main log data
            log_data_part = line[data_start:]
            iptables_match = self.iptables_regex.search(log_data_part)
            
            if not iptables_match:
                # Try a simpler approach - just extract key=value pairs
                data = self._extract_key_value_pairs(log_data_part)
                if not data:
                    return None  # Can't parse this line
            else:
                # Extract data from regex match
                data = {
                    "interface_in": iptables_match.group(1) or "",
                    "interface_out": iptables_match.group(2) or "",
                    "mac": iptables_match.group(3) or "",
                    "src": iptables_match.group(4) or "",
                    "dst": iptables_match.group(5) or "",
                    "length": iptables_match.group(6),
                    "tos": iptables_match.group(7),
                    "precedence": iptables_match.group(8),
                    "ttl": iptables_match.group(9),
                    "id": iptables_match.group(10),
                    "flags": iptables_match.group(11).strip() if iptables_match.group(11) else "",
                    "protocol": iptables_match.group(12) or "",
                    "src_port": iptables_match.group(13),
                    "dst_port": iptables_match.group(14),
                    "window": iptables_match.group(15),
                    "res": iptables_match.group(16),
                    "urgent_pointer": iptables_match.group(17)
                }
                
                # Clean up empty values
                data = {k: v for k, v in data.items() if v}
                
            # Determine action based on the chain/target if present
            action = "unknown"
            
            # Look for chain/target in the log
            chain_match = re.search(r'(?:PREFIX=|CHAIN=|chain=|rule=|target=)(\w+)', log_data_part, re.IGNORECASE)
            if chain_match:
                chain = chain_match.group(1).upper()
                if chain in ["DROP", "REJECT", "DENIED", "DENY", "BLOCK"]:
                    action = "block"
                elif chain in ["ACCEPT", "ALLOWED", "ALLOW", "PERMIT", "PASS"]:
                    action = "allow"
                else:
                    action = chain.lower()
            else:
                # Try to infer action from other parts of the log
                if "DROP" in log_data_part or "REJECT" in log_data_part:
                    action = "block"
                elif "ACCEPT" in log_data_part or "ALLOWED" in log_data_part:
                    action = "allow"
                elif "LOGDROP" in log_data_part:
                    action = "block"
                else:
                    # Default to "log" if we can't determine
                    action = "log"
                
            data["action"] = action
            
            # Add hostname and process if found
            if hostname:
                data["hostname"] = hostname
            if process:
                data["process"] = process
                
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
            protocol_str = data.get("protocol_name", data.get("protocol", "unknown")).upper()
            src_ip = data.get("src", "unknown")
            dst_ip = data.get("dst", "unknown")
            src_port = f":{data.get('src_port', '')}" if "src_port" in data else ""
            dst_port = f":{data.get('dst_port', '')}" if "dst_port" in data else ""
            
            message = f"{action.upper()} {protocol_str} {src_ip}{src_port} -> {dst_ip}{dst_port}"
            
            # Add interface information if available
            in_iface = data.get("interface_in")
            out_iface = data.get("interface_out")
            
            if in_iface or out_iface:
                iface_str = ""
                if in_iface:
                    iface_str += f"in:{in_iface} "
                if out_iface:
                    iface_str += f"out:{out_iface}"
                message += f" ({iface_str.strip()})"
                
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=line
            )
            
        except Exception as e:
            raise ParserError(f"Error parsing iptables log: {str(e)}")
            
    def _extract_key_value_pairs(self, text: str) -> Dict[str, str]:
        """Extract key=value pairs from iptables log

        Args:
            text: Log text to extract from

        Returns:
            Dictionary of extracted key-value pairs
        """
        result = {}
        
        # Pattern to match key=value pairs
        pattern = r'([A-Za-z0-9_]+)=([^ ]+)'
        
        # Find all matches
        for match in re.finditer(pattern, text):
            key = match.group(1).lower()
            value = match.group(2)
            
            # Clean up key names to match our convention
            if key == "in":
                key = "interface_in"
            elif key == "out":
                key = "interface_out"
            elif key == "spt":
                key = "src_port"
            elif key == "dpt":
                key = "dst_port"
                
            result[key] = value
            
        return result