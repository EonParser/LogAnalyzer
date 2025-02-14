import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

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
    parser_factory.register_parser("apache", ApacheLogParser)
    parser_factory.register_parser("nginx_access", NginxAccessLogParser)
    parser_factory.register_parser("nginx_error", NginxErrorLogParser)
    parser_factory.register_parser("syslog", SyslogParser)

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
@click.argument("directory", type=click.Path(exists=True))
@click.option("--pattern", "-p", default="*.log", help="File pattern")
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
