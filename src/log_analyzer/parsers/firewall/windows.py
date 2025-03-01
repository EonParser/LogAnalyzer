import re
from datetime import datetime
from typing import Dict, Optional, Any

from ..firewall_base import FirewallLogParser
from ...parsers.base import LogEntry, ParserError


class WindowsFirewallLogParser(FirewallLogParser):
    """Parser for Windows Firewall logs"""

    # Example log format:
    # 2023-05-23 14:47:34 DROP TCP 192.168.1.100 192.168.1.200 49152 80 - - - - - - - SEND
    
    # Windows Firewall log format (older W3C format)
    WIN_FW_PATTERN = r"^([0-9\-]+\s+[0-9:\.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)"
    
    # Windows Firewall log format (newer format)
    # Date Time Action Protocol Src-IP Dst-IP Src-Port Dst-Port Size Interface Direction
    WIN_FW_EXT_PATTERN = r"^([0-9\-]+\s+[0-9:\.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)"
    
    def __init__(self):
        """Initialize Windows Firewall log parser"""
        super().__init__()
        self.name = "windows_firewall"
        self.description = "Windows Firewall Log Parser"
        
        # Compile regex patterns
        self.win_fw_regex = re.compile(self.WIN_FW_PATTERN)
        self.win_fw_ext_regex = re.compile(self.WIN_FW_EXT_PATTERN)
        
        # Action mappings
        self.action_mappings = {
            "DROP": "block",
            "ALLOW": "allow",
            "DENY": "block",
            "OPEN": "allow",
            "CLOSE": "disconnect",
            "INFO-EVENTS-LOST": "info"
        }

    def supports_format(self, line: str) -> bool:
        """Check if line matches Windows Firewall log format"""
        # Check for date-time pattern at beginning of line
        date_pattern = r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}"
        if not re.match(date_pattern, line):
            return False
            
        # Check for action keywords
        action_keywords = ["ALLOW", "DROP", "DENY", "OPEN", "CLOSE"]
        has_action = any(action in line for action in action_keywords)
        
        # Check for common protocols
        protocols = ["TCP", "UDP", "ICMP", "IP"]
        has_protocol = any(f" {proto} " in line for proto in protocols)
        
        return has_action and has_protocol

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse Windows Firewall log line into structured data

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
                
            # Try extended format first
            ext_match = self.win_fw_ext_regex.match(line)
            if ext_match:
                return self._parse_extended_format(ext_match, line)
                
            # Try standard format
            std_match = self.win_fw_regex.match(line)
            if std_match:
                return self._parse_standard_format(std_match, line)
                
            # If none of the patterns match, try a more flexible approach
            return self._parse_flexible(line)
                
        except Exception as e:
            raise ParserError(f"Error parsing Windows Firewall log: {str(e)}")
    
    def _parse_extended_format(self, match, raw_line: str) -> Optional[LogEntry]:
        """Parse Windows Firewall extended format
        
        Args:
            match: Regex match object
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        try:
            # Extract fields from match
            timestamp_str = match.group(1)
            action = match.group(2)
            protocol = match.group(3)
            src_ip = match.group(4)
            dst_ip = match.group(5)
            src_port = match.group(6)
            dst_port = match.group(7)
            size = match.group(8)
            interface = match.group(9)
            direction = match.group(10)
            
            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            # Build data dictionary
            data = {
                "action": self.action_mappings.get(action.upper(), action.lower()),
                "protocol": protocol,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port if src_port != "-" else None,
                "dst_port": dst_port if dst_port != "-" else None,
                "size": size if size != "-" else None,
                "interface": interface if interface != "-" else None,
                "direction": direction if direction != "-" else None
            }
            
            # Clean up data
            data = {k: v for k, v in data.items() if v is not None}
            
            # Set interface_in/out based on direction
            if "interface" in data and "direction" in data:
                if data["direction"] in ["IN", "RECEIVE"]:
                    data["interface_in"] = data["interface"]
                elif data["direction"] in ["OUT", "SEND"]:
                    data["interface_out"] = data["interface"]
            
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
            action_str = data["action"].upper()
            protocol_str = data.get("protocol_name", protocol).upper()
            
            message_parts = [action_str, protocol_str]
            
            # Add source and destination info
            src_port_str = f":{src_port}" if src_port != "-" else ""
            dst_port_str = f":{dst_port}" if dst_port != "-" else ""
            message_parts.append(f"{src_ip}{src_port_str} -> {dst_ip}{dst_port_str}")
            
            # Add direction and interface if available
            if "direction" in data and "interface" in data:
                message_parts.append(f"({data['direction']}:{data['interface']})")
                
            message = " ".join(message_parts)
            
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=raw_line
            )
            
        except Exception as e:
            raise ParserError(f"Error parsing Windows Firewall extended format: {str(e)}")
    
    def _parse_standard_format(self, match, raw_line: str) -> Optional[LogEntry]:
        """Parse Windows Firewall standard format
        
        Args:
            match: Regex match object
            raw_line: Original raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        try:
            # Extract fields from match
            timestamp_str = match.group(1)
            action = match.group(2)
            protocol = match.group(3)
            src_ip = match.group(4)
            dst_ip = match.group(5)
            src_port = match.group(6)
            dst_port = match.group(7)
            
            # Parse remaining fields from the line
            parts = raw_line.split()
            if len(parts) > 7:
                # Try to find direction (usually at the end)
                direction = parts[-1] if parts[-1] in ["SEND", "RECEIVE"] else None
                
                # Look for interface info
                interface = None
                for idx, part in enumerate(parts[7:-1], 8):
                    if part in ["Ethernet", "WiFi", "LAN", "WAN"]:
                        interface = part
                        break
            else:
                direction = None
                interface = None
            
            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            # Build data dictionary
            data = {
                "action": self.action_mappings.get(action.upper(), action.lower()),
                "protocol": protocol,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port if src_port != "-" else None,
                "dst_port": dst_port if dst_port != "-" else None
            }
            
            # Add direction and interface if available
            if direction:
                data["direction"] = direction
            if interface:
                data["interface"] = interface
                
                # Set interface_in/out based on direction
                if direction in ["IN", "RECEIVE"]:
                    data["interface_in"] = interface
                elif direction in ["OUT", "SEND"]:
                    data["interface_out"] = interface
            
            # Clean up data
            data = {k: v for k, v in data.items() if v is not None}
            
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
            action_str = data["action"].upper()
            protocol_str = data.get("protocol_name", protocol).upper()
            
            message_parts = [action_str, protocol_str]
            
            # Add source and destination info
            src_port_str = f":{src_port}" if src_port != "-" else ""
            dst_port_str = f":{dst_port}" if dst_port != "-" else ""
            message_parts.append(f"{src_ip}{src_port_str} -> {dst_ip}{dst_port_str}")
            
            # Add direction and interface if available
            direction_str = ""
            if "direction" in data:
                direction_str = data["direction"]
            if "interface" in data:
                if direction_str:
                    direction_str += f":{data['interface']}"
                else:
                    direction_str = data["interface"]
                    
            if direction_str:
                message_parts.append(f"({direction_str})")
                
            message = " ".join(message_parts)
            
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=raw_line
            )
            
        except Exception as e:
            raise ParserError(f"Error parsing Windows Firewall standard format: {str(e)}")
    
    def _parse_flexible(self, line: str) -> Optional[LogEntry]:
        """Parse Windows Firewall log with a more flexible approach
        
        Args:
            line: Raw log line
            
        Returns:
            LogEntry if successful, None if invalid
        """
        try:
            # Split the line into parts
            parts = line.split()
            if len(parts) < 5:
                return None
                
            # First two parts should be date and time
            date_part = parts[0]
            time_part = parts[1]
            timestamp_str = f"{date_part} {time_part}"
            
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Try to handle other date formats
                try:
                    # Try common alternative formats
                    for fmt in ["%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                        try:
                            timestamp = datetime.strptime(timestamp_str, fmt)
                            break
                        except ValueError:
                            continue
                except ValueError:
                    # If all else fails, use current time
                    timestamp = datetime.now()
            
            # The next part should be the action
            action = parts[2]
            normalized_action = self.action_mappings.get(action.upper(), action.lower())
            
            # The next part should be the protocol
            protocol = parts[3]
            
            # Look for IP addresses
            ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
            ips = re.findall(ip_pattern, line)
            
            if len(ips) >= 2:
                src_ip = ips[0]
                dst_ip = ips[1]
            else:
                # Not enough IPs found
                return None
            
            # Look for ports (numbers after IPs)
            port_indices = []
            for i, ip in enumerate(ips[:2]):
                try:
                    ip_index = parts.index(ip)
                    if ip_index + 1 < len(parts) and parts[ip_index + 1].isdigit():
                        port_indices.append(ip_index + 1)
                except ValueError:
                    continue
            
            src_port = parts[port_indices[0]] if len(port_indices) > 0 else None
            dst_port = parts[port_indices[1]] if len(port_indices) > 1 else None
            
            # Look for direction at the end
            direction = None
            if parts[-1] in ["SEND", "RECEIVE", "IN", "OUT"]:
                direction = parts[-1]
            
            # Build data dictionary
            data = {
                "action": normalized_action,
                "protocol": protocol,
                "src": src_ip,
                "dst": dst_ip
            }
            
            if src_port:
                data["src_port"] = src_port
            if dst_port:
                data["dst_port"] = dst_port
            if direction:
                data["direction"] = direction
            
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
            action_str = normalized_action.upper()
            protocol_str = data.get("protocol_name", protocol).upper()
            
            message_parts = [action_str, protocol_str]
            
            # Add source and destination info
            src_port_str = f":{src_port}" if src_port else ""
            dst_port_str = f":{dst_port}" if dst_port else ""
            message_parts.append(f"{src_ip}{src_port_str} -> {dst_ip}{dst_port_str}")
            
            # Add direction if available
            if direction:
                message_parts.append(f"({direction})")
                
            message = " ".join(message_parts)
            
            # Create log entry
            return self.create_log_entry(
                timestamp=timestamp,
                message=message,
                parsed_data=data,
                raw_data=line
            )
            
        except Exception as e:
            raise ParserError(f"Error parsing Windows Firewall flexible format: {str(e)}")