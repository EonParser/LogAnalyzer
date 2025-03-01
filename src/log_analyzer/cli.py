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
    """Extract firewall-specific metrics from analysis results
    
    Args:
        results: Analysis results from LogAnalyzer
        
    Returns:
        Dictionary of firewall-specific metrics
    """
    metrics = {
        "allowed": 0,
        "blocked": 0,
        "disconnected": 0,
        "nat": 0,
        "unique_ips": set(),
        "blocked_ports": Counter(),
        "blocked_ips": Counter(),
        "traffic_sources": Counter(),
    }
    
    # Extract metrics from log entries
    entries = results.get("entries", [])
    for entry in entries:
        # Skip entries without metadata
        if not hasattr(entry, "metadata") or not entry.metadata:
            continue
            
        # Check if this is a firewall log
        if entry.metadata.get("log_type") != "firewall":
            continue
            
        # Count actions
        action = entry.metadata.get("action", "unknown")
        if action == "allow":
            metrics["allowed"] += 1
        elif action == "block":
            metrics["blocked"] += 1
        elif action == "disconnect":
            metrics["disconnected"] += 1
        elif action == "nat":
            metrics["nat"] += 1
        
        # Extract IP addresses
        if hasattr(entry, "parsed_data"):
            src_ip = entry.parsed_data.get("src")
            dst_ip = entry.parsed_data.get("dst")
            
            if src_ip:
                metrics["unique_ips"].add(src_ip)
                metrics["traffic_sources"][src_ip] += 1
            if dst_ip:
                metrics["unique_ips"].add(dst_ip)
            
            # Track blocked connections
            if action == "block":
                if src_ip:
                    metrics["blocked_ips"][src_ip] += 1
                    
                # Track blocked ports
                dst_port = entry.parsed_data.get("dst_port")
                if dst_port and dst_port.isdigit():
                    metrics["blocked_ports"][dst_port] += 1
    
    return metrics


def get_service_name(port: str) -> str:
    """Get service name for a port number
    
    Args:
        port: Port number as string
        
    Returns:
        Service name or "Unknown"
    """
    # Common port mappings
    port_map = {
        "22": "SSH",
        "23": "Telnet",
        "25": "SMTP",
        "53": "DNS",
        "80": "HTTP",
        "443": "HTTPS",
        "3389": "RDP",
        "1433": "SQL Server",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "137": "NetBIOS",
        "138": "NetBIOS",
        "139": "NetBIOS",
        "445": "SMB",
        "21": "FTP",
        "20": "FTP Data",
        "161": "SNMP",
        "162": "SNMP Trap",
        "389": "LDAP",
        "636": "LDAPS",
        "110": "POP3",
        "143": "IMAP",
        "993": "IMAPS",
        "995": "POP3S",
        "1723": "PPTP",
        "500": "IKE",
        "4500": "IKE NAT-T",
        "8080": "HTTP Proxy",
        "8443": "HTTPS Alt",
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