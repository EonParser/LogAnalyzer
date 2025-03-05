import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import Counter

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .core.analyzer import LogAnalyzer
from .parsers.apache import ApacheLogParser
from .parsers.base import ParserFactory
from .parsers.nginx import NginxAccessLogParser, NginxErrorLogParser
from .parsers.syslog import SyslogParser
from .parsers.firewall.firewall_parser import register_with_parser_factory
from .processors.pipeline import FilterStep, Pipeline
from .processors.transformers import TransformerFactory
from .utils.config import Config
from .utils.file_utils import estimate_line_count, get_file_info

console = Console()


def setup_logging(verbose: bool):
    """Configure logging with rich output"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(message)s", handlers=[RichHandler(rich_tracebacks=True)]
    )


def create_analyzer() -> LogAnalyzer:
    """Create and configure log analyzer"""
    parser_factory = ParserFactory()
    
    # Register standard parsers
    parser_factory.register_parser("apache", ApacheLogParser)
    parser_factory.register_parser("nginx_access", NginxAccessLogParser)
    parser_factory.register_parser("nginx_error", NginxErrorLogParser)
    parser_factory.register_parser("syslog", SyslogParser)
    
    # Register firewall parsers
    register_with_parser_factory(parser_factory)

    return LogAnalyzer(parser_factory=parser_factory)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--config", type=click.Path(exists=True), help="Configuration file")
def cli(verbose: bool, config: Optional[str]):
    """Log Analyzer - Advanced log analysis and processing tool"""
    setup_logging(verbose)
    if config:
        Config().load_file(config)


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--parser", "-p", help="Parser to use (auto-detect if not specified)")
@click.option("--filter", "-f", multiple=True, help="Filter expressions")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option("--format", "-fmt", type=click.Choice(["text", "json"]), default="text")
def analyze(
    files: List[str],
    parser: Optional[str],
    filter: List[str],
    output: Optional[str],
    format: str,
):
    """Analyze log files"""
    analyzer = create_analyzer()
    pipeline = Pipeline()

    # Add filters if specified
    for expr in filter:
        pipeline.add_step(FilterStep(f"filter_{expr}", eval(f"lambda e: {expr}")))

    # Add standard transformations
    pipeline.add_step(TransformerFactory.create_standard_transformer())

    total_results = {
        "total_entries": 0,
        "errors": {"count": 0, "messages": []},
        "start_time": datetime.now().isoformat(),
        "files": [],
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for file_path in files:
            path = Path(file_path)
            task = progress.add_task(
                f"Analyzing {path.name}...", total=estimate_line_count(path)
            )

            try:
                results = analyzer.analyze_file(
                    path, parser_name=parser, pipeline=pipeline
                )

                total_results["total_entries"] += results["total_entries"]
                total_results["errors"]["count"] += results["errors"]["count"]
                total_results["errors"]["messages"].extend(
                    results["errors"]["messages"]
                )
                total_results["files"].append({"name": str(path), "results": results})

                progress.update(task, completed=results["total_entries"])

            except Exception as e:
                logging.error(f"Error processing {path}: {e}")
                total_results["errors"]["count"] += 1
                total_results["errors"]["messages"].append(str(e))

    total_results["end_time"] = datetime.now().isoformat()

    # Output results
    if format == "json":
        if output:
            with open(output, "w") as f:
                json.dump(total_results, f, indent=2)
        else:
            console.print_json(data=total_results)
    else:
        table = Table(title="Analysis Results")
        table.add_column("File")
        table.add_column("Entries")
        table.add_column("Errors")
        table.add_column("Duration")

        for file_result in total_results["files"]:
            results = file_result["results"]
            table.add_row(
                file_result["name"],
                str(results["total_entries"]),
                str(results["errors"]["count"]),
                f"{results['duration_seconds']:.2f}s",
            )

        console.print(table)

        if output:
            with open(output, "w") as f:
                console = Console(file=f)
                console.print(table)


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--parser", "-p", help="Firewall parser to use (auto-detect if not specified)")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option("--format", "-fmt", type=click.Choice(["text", "json"]), default="json")
def analyze_firewall(
    files: List[str],
    parser: Optional[str],
    output: Optional[str],
    format: str,
):
    """Analyze firewall log files with specialized security analysis"""
    analyzer = create_analyzer()
    pipeline = Pipeline()

    # Add security-focused transformations
    pipeline.add_step(TransformerFactory.create_security_transformer())

    total_results = {
        "total_entries": 0,
        "summary": {
            "allowed": 0,
            "blocked": 0,
            "disconnected": 0,
            "nat": 0,
            "total_ips": 0,
            "top_blocked_ports": [],
            "top_blocked_ips": [],
            "top_traffic_sources": [],
            "blocked_percentage": 0.0,
        },
        "errors": {"count": 0, "messages": []},
        "start_time": datetime.now().isoformat(),
        "files": [],
    }

    # Sets to track unique IPs and connections across all files
    all_ips = set()
    
    # Counters for blocked ports and IPs
    blocked_ports = Counter()
    blocked_ips = Counter()
    traffic_sources = Counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for file_path in files:
            path = Path(file_path)
            task = progress.add_task(
                f"Analyzing firewall log {path.name}...", total=estimate_line_count(path)
            )

            try:
                # Try to use specified parser or auto-detect a firewall parser
                parser_name = parser if parser else "firewall"
                results = analyzer.analyze_file(
                    path, parser_name=parser_name, pipeline=pipeline
                )

                # Extract firewall-specific metrics
                firewall_metrics = extract_firewall_metrics(results)
                
                # Update summary counters
                total_results["total_entries"] += results["total_entries"]
                total_results["summary"]["allowed"] += firewall_metrics["allowed"]
                total_results["summary"]["blocked"] += firewall_metrics["blocked"]
                total_results["summary"]["disconnected"] += firewall_metrics["disconnected"]
                total_results["summary"]["nat"] += firewall_metrics["nat"]
                
                # Update unique IPs
                all_ips.update(firewall_metrics["unique_ips"])
                
                # Update counters for blocked ports and IPs
                for port, count in firewall_metrics["blocked_ports"].items():
                    blocked_ports[port] += count
                
                for ip, count in firewall_metrics["blocked_ips"].items():
                    blocked_ips[ip] += count
                    
                for ip, count in firewall_metrics["traffic_sources"].items():
                    traffic_sources[ip] += count
                
                # Track errors
                total_results["errors"]["count"] += results["errors"]["count"]
                total_results["errors"]["messages"].extend(
                    results["errors"]["messages"]
                )
                
                # Add file results
                total_results["files"].append({
                    "name": str(path),
                    "results": {
                        "total_entries": results["total_entries"],
                        "firewall_metrics": firewall_metrics,
                        "errors": {
                            "count": results["errors"]["count"],
                            "messages": results["errors"]["messages"]
                        }
                    }
                })

                progress.update(task, completed=results["total_entries"])

            except Exception as e:
                logging.error(f"Error processing firewall log {path}: {e}")
                total_results["errors"]["count"] += 1
                total_results["errors"]["messages"].append(str(e))

    # Update summary with calculated metrics
    total_results["summary"]["total_ips"] = len(all_ips)
    
    # Calculate blocked percentage
    total_traffic = (
        total_results["summary"]["allowed"] + 
        total_results["summary"]["blocked"]
    )
    if total_traffic > 0:
        total_results["summary"]["blocked_percentage"] = (
            total_results["summary"]["blocked"] / total_traffic * 100
        )
    
    # Get top 10 for various metrics
    total_results["summary"]["top_blocked_ports"] = [
        {"port": port, "service": get_service_name(port), "count": count}
        for port, count in blocked_ports.most_common(10)
    ]
    
    total_results["summary"]["top_blocked_ips"] = [
        {"ip": ip, "count": count}
        for ip, count in blocked_ips.most_common(10)
    ]
    
    total_results["summary"]["top_traffic_sources"] = [
        {"ip": ip, "count": count}
        for ip, count in traffic_sources.most_common(10)
    ]
    
    total_results["end_time"] = datetime.now().isoformat()

    # Output results
    if format == "json":
        if output:
            with open(output, "w") as f:
                json.dump(total_results, f, indent=2)
        else:
            console.print_json(data=total_results)
    else:
        # Print firewall summary as text tables
        print_firewall_summary(total_results, console)
        
        if output:
            with open(output, "w") as f:
                output_console = Console(file=f)
                print_firewall_summary(total_results, output_console)


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
                metrics["rules_triggered"][rule_id] += 1
    
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
    
    # Add percentage metrics
    total_traffic = metrics["allowed"] + metrics["blocked"]
    metrics["blocked_percentage"] = 0.0
    if total_traffic > 0:
        metrics["blocked_percentage"] = metrics["blocked"] / total_traffic * 100

    # Get top 10 for various categories
    metrics["top_blocked_ips"] = [{
        "ip": ip,
        "count": count,
        "type": classify_ip(ip)
    } for ip, count in metrics["blocked_ips"].most_common(10)]
    
    metrics["top_traffic_sources"] = [{
        "ip": ip,
        "count": count,
        "type": classify_ip(ip)
    } for ip, count in metrics["traffic_sources"].most_common(10)]
    
    metrics["top_blocked_ports"] = [{
        "port": port,
        "service": get_service_name(port),
        "count": count,
        "percentage": (count / metrics["blocked"] * 100) if metrics["blocked"] > 0 else 0
    } for port, count in metrics["blocked_ports"].most_common(10)]
    
    metrics["top_attacked_services"] = [{
        "service": get_service_name(port),
        "port": port,
        "count": count,
        "percentage": (count / metrics["blocked"] * 100) if metrics["blocked"] > 0 else 0
    } for port, count in metrics["blocked_ports"].most_common(10)]
    
    metrics["top_protocols"] = [{
        "protocol": protocol,
        "count": count
    } for protocol, count in metrics["protocols"].most_common(5)]
    
    metrics["top_block_reasons"] = [{
        "reason": reason if reason else "Unknown",
        "count": count
    } for reason, count in metrics["block_reasons"].most_common(5)]
    
    # Add hourly distribution statistics
    metrics["hourly_distribution"] = {
        "traffic": dict(metrics["hourly_traffic"]),
        "blocks": dict(metrics["hourly_blocks"])
    }
    
    # Calculate peak times
    if metrics["hourly_traffic"]:
        traffic_peak = max(metrics["hourly_traffic"].items(), key=lambda x: x[1])
        metrics["peak_traffic_hour"] = {
            "hour": traffic_peak[0],
            "count": traffic_peak[1]
        }
    
    if metrics["hourly_blocks"]:
        blocks_peak = max(metrics["hourly_blocks"].items(), key=lambda x: x[1])
        metrics["peak_blocks_hour"] = {
            "hour": blocks_peak[0],
            "count": blocks_peak[1]
        }
    
    # Add attack summary
    metrics["attack_summary"] = {
        "port_scan_attempts": metrics["port_scan_attempts"],
        "brute_force_attempts": metrics["brute_force_attempts"],
        "dos_attempts": metrics["dos_attempts"],
        "suspicious_ips_count": len(metrics["suspicious_ips"]),
        "suspicious_ips": list(metrics["suspicious_ips"])
    }
    
    return metrics

def classify_ip(ip: str) -> str:
    """Classify an IP address as internal, external, or special
    
    Args:
        ip: IP address to classify
        
    Returns:
        Classification of the IP
    """
    import ipaddress
    
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
    """Get service name for a port number with expanded list
    
    Args:
        port: Port number as string
        
    Returns:
        Service name or "Unknown"
    """
    # More comprehensive port mappings
    port_map = {
        "1": "TCPMUX",
        "5": "RJE",
        "7": "ECHO",
        "9": "DISCARD",
        "11": "SYSTAT",
        "13": "DAYTIME",
        "17": "QOTD",
        "18": "MSP",
        "19": "CHARGEN",
        "20": "FTP-DATA",
        "21": "FTP",
        "22": "SSH",
        "23": "TELNET",
        "25": "SMTP",
        "37": "TIME",
        "42": "NAMESERVER",
        "43": "NICNAME",
        "49": "TACACS",
        "53": "DNS",
        "67": "DHCP/BOOTP",
        "68": "DHCP/BOOTP",
        "69": "TFTP",
        "70": "GOPHER",
        "79": "FINGER",
        "80": "HTTP",
        "88": "KERBEROS",
        "102": "MS EXCHANGE",
        "110": "POP3",
        "111": "SUNRPC",
        "113": "IDENT",
        "119": "NNTP",
        "123": "NTP",
        "135": "MS-RPC",
        "137": "NETBIOS-NS",
        "138": "NETBIOS-DGM",
        "139": "NETBIOS-SSN",
        "143": "IMAP",
        "161": "SNMP",
        "162": "SNMP-TRAP",
        "177": "XDMCP",
        "179": "BGP",
        "201": "APPLETALK",
        "264": "BGMP",
        "318": "TSP",
        "381": "HP OPENVIEW",
        "383": "HP OPENVIEW",
        "389": "LDAP",
        "411": "DIRECT CONNECT",
        "412": "DIRECT CONNECT",
        "443": "HTTPS",
        "445": "MS-DS",
        "464": "KERBEROS",
        "465": "SMTPS",
        "497": "RETROSPECT",
        "500": "ISAKMP",
        "512": "REXEC",
        "513": "RLOGIN",
        "514": "SYSLOG",
        "515": "LPD/LPR",
        "520": "RIP",
        "521": "RIPNG",
        "540": "UUCP",
        "554": "RTSP",
        "546": "DHCP-CLIENT",
        "547": "DHCP-SERVER",
        "560": "RMONITOR",
        "563": "NNTPS",
        "587": "SUBMISSION",
        "591": "FILEMAKER",
        "593": "MS-RPC",
        "631": "IPP",
        "636": "LDAPS",
        "639": "MSDP",
        "646": "LDP",
        "691": "MS EXCHANGE",
        "860": "ISCSI",
        "873": "RSYNC",
        "902": "VMWARE",
        "989": "FTPS-DATA",
        "990": "FTPS",
        "993": "IMAPS",
        "995": "POP3S",
        "1025": "MS RPC",
        "1026": "MS RPC",
        "1027": "MS RPC",
        "1028": "MS RPC",
        "1029": "MS RPC",
        "1080": "SOCKS",
        "1080": "MYSPACE",
        "1194": "OPENVPN",
        "1214": "KAZAA",
        "1241": "NESSUS",
        "1311": "DELL OPENMANAGE",
        "1337": "WASTE",
        "1433": "MS-SQL",
        "1434": "MS-SQL",
        "1512": "WINS",
        "1589": "CISCO VQP",
        "1701": "L2TP",
        "1723": "PPTP",
        "1725": "STEAM",
        "1741": "CITRIX",
        "1755": "MS-STREAMING",
        "1812": "RADIUS",
        "1813": "RADIUS",
        "1863": "MSN",
        "1985": "CISCO HSRP",
        "2000": "CISCO SCCP",
        "2002": "CISCO ACS",
        "2049": "NFS",
        "2082": "CPANEL",
        "2083": "CPANEL",
        "2100": "ORACLE XDB",
        "2222": "DIRECTADMIN",
        "2302": "HALO",
        "2483": "ORACLE",
        "2484": "ORACLE",
        "2745": "BAGLE.H",
        "2967": "SYMANTEC AV",
        "3050": "INTERBASE",
        "3074": "XBOX LIVE",
        "3124": "HTTP PROXY",
        "3127": "MYDOOM",
        "3128": "HTTP PROXY",
        "3222": "GLBP",
        "3260": "ISCSI TARGET",
        "3306": "MYSQL",
        "3389": "RDP",
        "3689": "ITUNES",
        "3690": "SVN",
        "3724": "WORLD OF WARCRAFT",
        "3784": "VENTRILO",
        "3785": "VENTRILO",
        "4333": "MSQL",
        "4444": "BLASTER",
        "4500": "IPSEC NAT-T",
        "4664": "GOOGLE DESKTOP",
        "4672": "EDONKEY",
        "4899": "RADMIN",
        "5000": "UPnP",
        "5001": "SLINGBOX",
        "5004": "RTP",
        "5005": "RTP",
        "5050": "YAHOO MESSENGER",
        "5060": "SIP",
        "5190": "AIM/ICQ",
        "5222": "XMPP/JABBER",
        "5223": "XMPP/JABBER",
        "5432": "POSTGRESQL",
        "5500": "VNC",
        "5554": "SASSER",
        "5631": "PCANYWHERE",
        "5632": "PCANYWHERE",
        "5800": "VNC",
        "5900": "VNC",
        "6000": "X11",
        "6001": "X11",
        "6112": "BLIZZARD",
        "6129": "DAMEWARE",
        "6257": "WINMX",
        "6346": "GNUTELLA",
        "6347": "GNUTELLA",
        "6379": "REDIS",
        "6881": "BITTORRENT",
        "6969": "BITTORRENT",
        "7212": "GHOSTSURF",
        "7648": "CU-SEEME",
        "7649": "CU-SEEME",
        "8000": "HTTP ALT",
        "8080": "HTTP PROXY",
        "8086": "KASPERSKY",
        "8087": "KASPERSKY",
        "8118": "PRIVOXY",
        "8200": "VMWARE SERVER",
        "8500": "ADOBE COLDFUSION",
        "8767": "TEAMSPEAK",
        "8866": "BAGLE",
        "9100": "PRINTER",
        "9101": "BACULA",
        "9102": "BACULA",
        "9103": "BACULA",
        "9119": "MXIT",
        "9800": "WEBDAV",
        "9898": "MONKEYCOM",
        "9988": "RBOT/SPYBOT",
        "9999": "URCHIN",
        "10000": "WEBMIN",
        "11371": "OPENPGP",
        "12035": "SECOND LIFE",
        "12036": "SECOND LIFE",
        "12345": "NETBUS",
        "13720": "NETBACKUP",
        "13721": "NETBACKUP",
        "14567": "BATTLEFIELD",
        "15118": "DIPNET",
        "19226": "PCANYWHERE",
        "19638": "ENSIM",
        "20000": "USERMIN",
        "24800": "SYNERGY",
        "25999": "XFIRE",
        "27015": "STEAM",
        "27374": "SUB7",
        "28960": "CALL OF DUTY",
        "31337": "BACK ORIFICE",
        "33434": "TRACEROUTE"
    }
    
    return port_map.get(port, "Unknown")

def print_firewall_summary(results: Dict[str, Any], console: Console = console):
    """Print a formatted summary of firewall analysis results
    
    Args:
        results: Firewall analysis results
        console: Rich console to print to
    """
    summary = results["summary"]
    
    # Print overall summary
    console.print("\n[bold]Firewall Analysis Summary[/bold]")
    
    table = Table(title="Traffic Summary")
    table.add_column("Metric")
    table.add_column("Value")
    
    table.add_row(
        "Total Log Entries", 
        str(results["total_entries"])
    )
    table.add_row(
        "Allowed Connections", 
        f"{summary['allowed']} ({summary['allowed'] / results['total_entries'] * 100:.1f}%)"
    )
    table.add_row(
        "Blocked Connections", 
        f"{summary['blocked']} ({summary['blocked'] / results['total_entries'] * 100:.1f}%)"
    )
    table.add_row(
        "Disconnected Connections", 
        str(summary['disconnected'])
    )
    table.add_row(
        "NAT Operations", 
        str(summary['nat'])
    )
    table.add_row(
        "Unique IP Addresses", 
        str(summary['total_ips'])
    )
    console.print(table)
    
    # Print top blocked ports
    console.print("\n[bold]Top Blocked Ports[/bold]")
    
    if not summary['top_blocked_ports']:
        console.print("[italic]No blocked ports detected[/italic]")
    else:
        table = Table()
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Count")
        
        for entry in summary['top_blocked_ports']:
            table.add_row(
                entry['port'],
                entry['service'],
                str(entry['count'])
            )
        
        console.print(table)
    
    # Print top blocked IPs
    console.print("\n[bold]Top Blocked Source IPs[/bold]")
    
    if not summary['top_blocked_ips']:
        console.print("[italic]No blocked source IPs detected[/italic]")
    else:
        table = Table()
        table.add_column("IP Address")
        table.add_column("Block Count")
        
        for entry in summary['top_blocked_ips']:
            table.add_row(
                entry['ip'],
                str(entry['count'])
            )
        
        console.print(table)
    
    # Print top traffic sources
    console.print("\n[bold]Top Traffic Sources[/bold]")
    
    if not summary['top_traffic_sources']:
        console.print("[italic]No traffic sources detected[/italic]")
    else:
        table = Table()
        table.add_column("IP Address")
        table.add_column("Connection Count")
        
        for entry in summary['top_traffic_sources']:
            table.add_row(
                entry['ip'],
                str(entry['count'])
            )
        
        console.print(table)
        
    # Print errors
    if results["errors"]["count"] > 0:
        console.print(f"\n[bold red]Errors: {results['errors']['count']}[/bold red]")
        
        if len(results["errors"]["messages"]) > 5:
            for message in results["errors"]["messages"][:5]:
                console.print(f"- {message}")
            console.print(f"... and {len(results['errors']['messages']) - 5} more errors")
        else:
            for message in results["errors"]["messages"]:
                console.print(f"- {message}")


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--pattern", "-p", default="*.log*", help="File pattern")
@click.option("--recursive/--no-recursive", default=True, help="Scan recursively")
def scan(directory: str, pattern: str, recursive: bool):
    """Scan directory for log files"""
    path = Path(directory)

    table = Table(title="Log Files")
    table.add_column("File")
    table.add_column("Size")
    table.add_column("Modified")
    table.add_column("Type")

    for file_path in path.rglob(pattern) if recursive else path.glob(pattern):
        info = get_file_info(file_path)
        table.add_row(
            str(file_path.relative_to(path)),
            info["size_human"],
            info["modified"].strftime("%Y-%m-%d %H:%M:%S"),
            info["mime_type"],
        )

    console.print(table)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--lines", "-n", default=10, help="Number of lines")
@click.option("--follow/--no-follow", "-f", default=False, help="Follow file")
def tail(file: str, lines: int, follow: bool):
    """Display the last lines of a log file"""
    from .utils.file_utils import tail as tail_file

    path = Path(file)
    last_lines = tail_file(path, lines)

    for line in last_lines:
        console.print(line)

    if follow:
        import time

        with open(path) as f:
            f.seek(0, 2)  # Go to end
            while True:
                line = f.readline()
                if line:
                    console.print(line.rstrip())
                else:
                    time.sleep(0.1)


@cli.command()
def list_parsers():
    """List available log parsers"""
    analyzer = create_analyzer()

    table = Table(title="Available Parsers")
    table.add_column("Name")
    table.add_column("Description")

    for name, parser_class in analyzer.parser_factory._parsers.items():
        table.add_row(name, parser_class.__doc__ or "No description")

    console.print(table)


if __name__ == "__main__":
    cli()