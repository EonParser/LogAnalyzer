"""
Enhanced Firewall Metrics Module

This module provides functions for extracting comprehensive metrics from firewall logs
"""

from collections import Counter, defaultdict
from typing import Dict, Any, Set
import ipaddress
import re

def extract_firewall_metrics(results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract enhanced firewall-specific metrics from analysis results
    
    Args:
        results: Analysis results from LogAnalyzer
        
    Returns:
        Dictionary of firewall-specific metrics with enhanced details
    """
    metrics = {
        # Basic counters
        "allowed": 0,
        "blocked": 0,
        "disconnected": 0,
        "nat": 0,
        
        # IP tracking
        "unique_ips": set(),
        "blocked_ips": Counter(),
        "traffic_sources": Counter(),
        "traffic_destinations": Counter(),
        
        # Port tracking
        "blocked_ports": Counter(),
        "target_ports": Counter(),
        "source_ports": Counter(),
        
        # Protocol tracking
        "protocols": Counter(),
        "blocked_protocols": Counter(),
        
        # Interface tracking
        "interfaces": Counter(),
        "interface_blocks": Counter(),
        
        # Time-based metrics
        "hourly_traffic": defaultdict(int),
        "hourly_blocks": defaultdict(int),
        
        # Rule tracking
        "rules_triggered": Counter(),
        "block_reasons": Counter(),
        
        # Attack pattern detection
        "port_scan_attempts": 0,
        "brute_force_attempts": 0,
        "dos_attempts": 0,
        "suspicious_ips": set()
    }
    
    # Scan detection parameters
    port_scan_threshold = 5  # Consider it a port scan if an IP hits X different ports
    brute_force_threshold = 3  # Consider it a brute force if X failed attempts to same service
    high_rate_threshold = 20  # Consider it suspicious if more than X requests per minute
    
    # Keep track of unique port hits per IP for port scan detection
    ip_port_hits = defaultdict(set)
    # Keep track of failed auth attempts per IP for brute force detection
    ip_auth_failures = Counter()
    # Keep track of request timestamps per IP for rate detection
    ip_request_times = defaultdict(list)
    
    # Extract metrics from log entries
    entries = results.get("entries", [])
    for entry in entries:
        # Skip entries without metadata
        if not hasattr(entry, "metadata") or not entry.metadata:
            continue
            
        # Check if this is a firewall log
        if entry.metadata.get("log_type") != "firewall":
            continue
        
        # Count actions by type
        action = entry.metadata.get("action", "unknown")
        if action == "allow":
            metrics["allowed"] += 1
        elif action == "block":
            metrics["blocked"] += 1
        elif action == "disconnect":
            metrics["disconnected"] += 1
        elif action == "nat":
            metrics["nat"] += 1
        
        # Add to hourly traffic
        if hasattr(entry, "timestamp"):
            hour = entry.timestamp.strftime("%Y-%m-%d %H:00")
            metrics["hourly_traffic"][hour] += 1
            
            if action == "block":
                metrics["hourly_blocks"][hour] += 1
        
        # Extract data from parsed content
        if hasattr(entry, "parsed_data"):
            parsed_data = entry.parsed_data
            
            # Process IP addresses
            src_ip = parsed_data.get("src")
            dst_ip = parsed_data.get("dst")
            
            if src_ip:
                metrics["unique_ips"].add(src_ip)
                metrics["traffic_sources"][src_ip] += 1
                
                # Add timestamp for rate detection
                if hasattr(entry, "timestamp"):
                    ip_request_times[src_ip].append(entry.timestamp)
            
            if dst_ip:
                metrics["unique_ips"].add(dst_ip)
                metrics["traffic_destinations"][dst_ip] += 1
            
            # Process ports
            src_port = parsed_data.get("src_port")
            dst_port = parsed_data.get("dst_port")
            
            if src_port and isinstance(src_port, (str, int)):
                # Ensure port is handled as string for consistency
                src_port = str(src_port)
                metrics["source_ports"][src_port] += 1
            
            if dst_port and isinstance(dst_port, (str, int)):
                # Ensure port is handled as string for consistency
                dst_port = str(dst_port)
                metrics["target_ports"][dst_port] += 1
                
                # Track unique port hits per source IP for port scan detection
                if src_ip and dst_port:
                    ip_port_hits[src_ip].add(dst_port)
            
            # Track blocked data
            if action == "block":
                if src_ip:
                    metrics["blocked_ips"][src_ip] += 1
                
                if dst_port:
                    metrics["blocked_ports"][dst_port] += 1
                    
                # Track reason for block if available
                reason = parsed_data.get("reason", entry.metadata.get("reason"))
                if reason:
                    metrics["block_reasons"][reason] += 1
                
                # For auth failures, increment brute force counter
                if "auth" in str(entry.message).lower() or "login" in str(entry.message).lower():
                    if src_ip:
                        ip_auth_failures[src_ip] += 1
            
            # Track protocol information
            protocol = parsed_data.get("protocol")
            if protocol:
                metrics["protocols"][protocol] += 1
                
                if action == "block":
                    metrics["blocked_protocols"][protocol] += 1
            
            # Track interface information
            interface_in = parsed_data.get("interface_in")
            interface_out = parsed_data.get("interface_out")
            
            if interface_in:
                metrics["interfaces"][f"in:{interface_in}"] += 1
                
                if action == "block":
                    metrics["interface_blocks"][f"in:{interface_in}"] += 1
                    
            if interface_out:
                metrics["interfaces"][f"out:{interface_out}"] += 1
                
                if action == "block":
                    metrics["interface_blocks"][f"out:{interface_out}"] += 1
            
            # Track rule information if available
            rule_id = parsed_data.get("rule_id", parsed_data.get("connection_id"))
            if rule_id:
                metrics["rules_triggered"][str(rule_id)] += 1
    
    # Process the collected data to detect attack patterns
    for ip, ports in ip_port_hits.items():
        if len(ports) >= port_scan_threshold:
            metrics["port_scan_attempts"] += 1
            metrics["suspicious_ips"].add(ip)
    
    for ip, failures in ip_auth_failures.items():
        if failures >= brute_force_threshold:
            metrics["brute_force_attempts"] += 1
            metrics["suspicious_ips"].add(ip)
    
    # Detect high request rates (potential DoS)
    for ip, timestamps in ip_request_times.items():
        if len(timestamps) < high_rate_threshold:
            continue
            
        # Sort timestamps
        sorted_times = sorted(timestamps)
        
        # Check if there are periods with high request rates
        for i in range(len(sorted_times) - high_rate_threshold):
            start = sorted_times[i]
            end = sorted_times[i + high_rate_threshold - 1]
            
            # If high_rate_threshold requests happened within 60 seconds
            if (end - start).total_seconds() <= 60:
                metrics["dos_attempts"] += 1
                metrics["suspicious_ips"].add(ip)
                break
    
    return metrics

def classify_ip(ip: str) -> str:
    """Classify an IP address as internal, external, or special
    
    Args:
        ip: IP address to classify
        
    Returns:
        Classification of the IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        if ip_obj.is_private:
            return "Internal"
        elif ip_obj.is_loopback:
            return "Loopback"
        elif ip_obj.is_multicast:
            return "Multicast"
        elif ip_obj.is_reserved:
            return "Reserved"
        else:
            return "External"
    except ValueError:
        return "Invalid"

def get_service_name(port: str) -> str:
    """Get service name for a port number
    
    Args:
        port: Port number as string
        
    Returns:
        Service name or "Unknown"
    """
    # Common port mappings
    port_map = {
        "1": "TCPMUX",
        "20": "FTP-DATA",
        "21": "FTP",
        "22": "SSH",
        "23": "TELNET",
        "25": "SMTP",
        "37": "TIME",
        "53": "DNS",
        "67": "DHCP/BOOTP",
        "68": "DHCP/BOOTP",
        "69": "TFTP",
        "80": "HTTP",
        "88": "KERBEROS",
        "110": "POP3",
        "119": "NNTP",
        "123": "NTP",
        "135": "MS-RPC",
        "137": "NETBIOS-NS",
        "138": "NETBIOS-DGM",
        "139": "NETBIOS-SSN",
        "143": "IMAP",
        "161": "SNMP",
        "162": "SNMP-TRAP",
        "389": "LDAP",
        "443": "HTTPS",
        "445": "SMB",
        "465": "SMTPS",
        "500": "IKE",
        "514": "SYSLOG",
        "587": "SUBMISSION",
        "636": "LDAPS",
        "993": "IMAPS",
        "995": "POP3S",
        "1433": "SQL Server",
        "1701": "L2TP",
        "1723": "PPTP",
        "3306": "MySQL",
        "3389": "RDP",
        "4500": "IKE NAT-T",
        "5432": "PostgreSQL",
        "8080": "HTTP Proxy",
        "8443": "HTTPS Alt",
    }
    
    return port_map.get(port, "Unknown")