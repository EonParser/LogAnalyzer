import asyncio
from collections import defaultdict
import json
import logging
import os
import shutil
import tempfile
from urllib import request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..core.analyzer import LogAnalyzer
from ..parsers.apache import ApacheErrorLogParser, ApacheLogParser
from ..parsers.base import ParserFactory, SimpleLineParser
from ..parsers.custom import IncidentLogParser
from ..parsers.nginx import NginxAccessLogParser, NginxErrorLogParser
from ..parsers.syslog import SyslogParser
from ..parsers.firewall.firewall_parser import register_with_parser_factory
from ..processors.pipeline import FilterStep, Pipeline, ProcessingStep
from ..processors.transformers import TransformerFactory
from .log_processor import LogProcessor

logging.basicConfig(level=logging.DEBUG)
app = FastAPI(title="Log Analyzer API")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzer
analyzer = None

# Store analysis tasks
tasks: Dict[str, Dict[str, Any]] = {}

def create_analyzer():
    """Create and configure analyzer instance"""
    global analyzer
    if analyzer is not None:
        return analyzer
        
    parser_factory = ParserFactory()
    
    # Register parsers with correct names
    parsers = {
        "apache_access": ApacheLogParser,
        "apache_error": ApacheErrorLogParser,
        "nginx_access": NginxAccessLogParser,
        "nginx_error": NginxErrorLogParser,
        "syslog": SyslogParser
    }
    
    for name, parser_class in parsers.items():
        parser_factory.register_parser(name, parser_class)
        logging.info(f"Registered parser: {name}")

    # Register firewall parsers
    register_with_parser_factory(parser_factory)
    
    analyzer = LogAnalyzer(parser_factory=parser_factory)
    logging.info(f"Available parsers: {list(parser_factory._parsers.keys())}")
    return analyzer

# Initialize analyzer and processor
analyzer = create_analyzer()
log_processor = LogProcessor(analyzer)

class AnalysisRequest(BaseModel):
    parser: Optional[str] = None
    filters: Optional[List[str]] = None


class AnalysisResponse(BaseModel):
    task_id: str
    status: str
    created_at: datetime


@app.post("/analyze")
async def analyze_logs(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    parser: Optional[str] = Form(None),
    filters: Optional[str] = Form(None),
    log_type: Optional[str] = Form("standard"),  # Add log_type parameter
):
    try:
        task_id = str(uuid.uuid4())
        saved_files = []

        # Save uploaded files
        for file in files:
            temp_dir = Path(tempfile.gettempdir()) / "log_analyzer"
            temp_dir.mkdir(exist_ok=True)
            temp_path = temp_dir / f"{task_id}_{file.filename}"

            logging.info(f"Saving file {file.filename} to {temp_path}")
            
            # Make sure we're at the start of the file
            await file.seek(0)
            content = await file.read()
            
            logging.info(f"File content length: {len(content)} bytes")
            logging.info(f"File content sample: {content[:200]}")
            
            # Ensure content is valid before saving
            if len(content) > 0:
                temp_path.write_bytes(content)
                logging.info(f"File saved to {temp_path}")
                saved_files.append({"path": temp_path, "filename": file.filename})
            else:
                logging.error(f"Empty file content for {file.filename}")

        tasks[task_id] = {
            "status": "pending",
            "created_at": datetime.now(),
            "files": [f["filename"] for f in saved_files],
            "results": None,
            "error": None,
            "temp_files": saved_files,
            "log_type": log_type,  # Store log_type
        }

        # Choose default parser based on log type
        default_parser = "firewall" if log_type == "firewall" else "simple"
        
        background_tasks.add_task(
            process_logs,
            task_id,
            saved_files,
            parser or default_parser,
            filters.split(",") if filters else None,
            log_type,  # Pass log_type to process_logs
        )

        return {
            "task_id": task_id,
            "status": "pending",
            "created_at": tasks[task_id]["created_at"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def process_logs(
    task_id: str, 
    saved_files: List[dict], 
    parser_name: Optional[str], 
    filters: Optional[List[str]],
    log_type: str = "standard",  # Add log_type parameter
):
    """Process uploaded log files"""
    try:
        logging.info(f"Starting processing task {task_id} with log_type: {log_type}")
        tasks[task_id]["status"] = "processing"

        try:
            # Create pipeline
            pipeline = Pipeline()
            
            # Add filters if specified
            if filters and len(filters) > 0:
                for i, filter_expr in enumerate(filters):
                    try:
                        pipeline.add_step(FilterStep(f"filter_{i}", eval(f"lambda e: {filter_expr}")))
                    except Exception as filter_err:
                        logging.warning(f"Failed to create filter from expression '{filter_expr}': {str(filter_err)}")

            # Create appropriate transformer based on log type
            transformer = None
            if log_type == "firewall":
                logging.info(f"Using security transformer for firewall logs")
                transformer = TransformerFactory.create_security_transformer()
                # Add the transformer as a step to the pipeline
                class TransformerStep(ProcessingStep):
                    def __init__(self, name, func):
                        super().__init__(name)
                        self.func = func
                    
                    def process(self, entry):
                        return self.func(entry)
                
                pipeline.add_step(TransformerStep("security_transformer", transformer))
            else:
                logging.info(f"Using standard transformer for logs")
                transformer = TransformerFactory.create_standard_transformer()
                pipeline.add_step(TransformerStep("standard_transformer", transformer))

            # Process logs appropriately based on log type
            if log_type == "firewall":
                # Process as firewall logs
                combined_results = await process_firewall_logs(
                    saved_files,
                    parser_name=parser_name,
                    pipeline=pipeline
                )
            else:
                # Process as standard logs
                combined_results = await log_processor.process_files(
                    saved_files,
                    parser_name=parser_name,
                    filters=filters
                )
            
            # Update task with results
            tasks[task_id].update({
                "status": "completed",
                "completed_at": datetime.now(),
                "results": combined_results
            })
            
            # Log completion message with appropriate entry count
            if log_type == "firewall":
                entries_count = combined_results.get("firewall_analysis", {}).get("summary", {}).get("total_entries", 0)
            else:
                entries_count = combined_results.get("summary", {}).get("total_entries", 0)
                
            logging.info(
                f"Task {task_id} completed successfully. "
                f"Processed {entries_count} entries"
            )
            
        except Exception as e:
            logging.exception("Error processing logs")

            # Create minimal results if possible
            minimal_results = {
                'summary': {
                    'total_entries': 0,
                    'error_rate': "0.0%",
                    'average_response_time': "0ms",
                    'unique_ips': 0,
                    'date_range': {'start': 'N/A', 'end': 'N/A', 'duration': 'N/A'}
                }
            }
            
            tasks[task_id].update({
                "status": "failed",
                "completed_at": datetime.now(),
                "error": f"Error processing logs: {str(e)}",
                "results": minimal_results  # Provide minimal results to avoid frontend errors
            })
            
    except Exception as e:
        logging.exception("Error in process_logs")
        tasks[task_id].update({
            "status": "failed",
            "completed_at": datetime.now(),
            "error": str(e)
        })

async def process_firewall_logs(saved_files: List[Dict], parser_name: str, pipeline: Pipeline) -> Dict[str, Any]:
    """Process firewall log files and extract firewall-specific metrics
    
    Args:
        saved_files: List of file info dictionaries
        parser_name: Name of parser to use
        pipeline: Processing pipeline
        
    Returns:
        Dictionary with firewall analysis results
    """
    from collections import Counter
    import traceback

    logging.info(f"Starting firewall log analysis with parser: {parser_name}")
    
    # Initialize metrics
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
    
    all_entries = []
    total_entries = 0
    error_count = 0
    error_messages = []
    
    # Process each file
    for file_info in saved_files:
        try:
            file_path = file_info["path"]
            filename = file_info["filename"]
            logging.info(f"Processing firewall file: {filename}")
            
            # Debug: Read sample of file content
            try:
                with open(file_path, "r") as f:
                    sample_lines = [next(f) for _ in range(5) if f]
                    logging.info(f"Sample lines from {filename}:")
                    for i, line in enumerate(sample_lines):
                        logging.info(f"  Line {i+1}: {line.strip()}")
            except Exception as read_error:
                logging.error(f"Error reading sample from file: {str(read_error)}")
            
            # Analyze file
            logging.info(f"Analyzing file {file_path} with parser {parser_name}")
            
            try:
                # If the pipeline is from TransformerFactory, it's a function not a Pipeline object
                # Create a simple adapter to make it work with analyze_file
                if callable(pipeline) and not hasattr(pipeline, 'process'):
                    transformer_func = pipeline
                    
                    class TransformerAdapter:
                        def process(self, entry):
                            return transformer_func(entry)
                    
                    pipeline_obj = TransformerAdapter()
                else:
                    pipeline_obj = pipeline
                
                results = analyzer.analyze_file(
                    file_path,
                    parser_name=parser_name,
                    pipeline=pipeline_obj
                )
                
                # Check if we got results back
                if not results:
                    logging.error(f"No results returned from analyzer for {filename}")
                    continue
                
                entries = results.get("entries", [])
                logging.info(f"Analysis found {len(entries)} entries in {filename}")
                
                if not entries:
                    logging.warning(f"No entries found in {filename}")
                    continue
                
                # Process entries and extract metrics
                firewall_entries_count = 0
                
                for entry in entries:
                    total_entries += 1
                    
                    # Debug log the entry data
                    logging.debug(f"Entry: {entry.message if hasattr(entry, 'message') else 'No message'}")
                    logging.debug(f"Metadata: {entry.metadata if hasattr(entry, 'metadata') else 'No metadata'}")
                    
                    # Skip entries without metadata
                    if not hasattr(entry, "metadata") or not entry.metadata:
                        logging.debug("Entry has no metadata, skipping")
                        continue
                        
                    # Check if this is a firewall log
                    log_type = entry.metadata.get("log_type")
                    if log_type != "firewall":
                        logging.debug(f"Entry log_type is {log_type}, not firewall")
                        continue
                    
                    firewall_entries_count += 1
                    all_entries.append(entry)
                    
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
                            if dst_port:
                                # Convert to string to ensure consistent handling
                                port_str = str(dst_port)
                                metrics["blocked_ports"][port_str] += 1
                
                logging.info(f"Processed {firewall_entries_count} firewall entries from {filename}")
                
                # Add any errors from this file
                if "errors" in results and results["errors"]:
                    if isinstance(results["errors"], dict) and "messages" in results["errors"]:
                        file_errors = results["errors"]["messages"]
                        error_count += len(file_errors)
                        error_messages.extend(file_errors[:10])  # Add up to 10 error messages
                    elif isinstance(results["errors"], list):
                        error_count += len(results["errors"])
                        error_messages.extend([str(err) for err in results["errors"][:10]])
                
            except Exception as analysis_error:
                error_message = f"Error analyzing {filename}: {str(analysis_error)}"
                logging.error(error_message)
                logging.error(traceback.format_exc())
                error_count += 1
                error_messages.append(error_message)
            
        except Exception as e:
            error_message = f"Error processing {file_info['filename']}: {str(e)}"
            logging.error(error_message)
            logging.error(traceback.format_exc())
            error_count += 1
            error_messages.append(error_message)
    
    # Log metrics summary
    logging.info(f"Firewall analysis summary:")
    logging.info(f"  Total entries: {total_entries}")
    logging.info(f"  Firewall entries: {len(all_entries)}")
    logging.info(f"  Allowed connections: {metrics['allowed']}")
    logging.info(f"  Blocked connections: {metrics['blocked']}")
    logging.info(f"  Unique IPs: {len(metrics['unique_ips'])}")
    
    # Log top 5 blocked ports and IPs
    if metrics['blocked_ports']:
        logging.info("  Top blocked ports:")
        for port, count in metrics['blocked_ports'].most_common(5):
            logging.info(f"    Port {port}: {count} times")
    
    if metrics['blocked_ips']:
        logging.info("  Top blocked IPs:")
        for ip, count in metrics['blocked_ips'].most_common(5):
            logging.info(f"    IP {ip}: {count} times")
    
    # Calculate blocked percentage
    total_traffic = metrics["allowed"] + metrics["blocked"]
    blocked_percentage = 0
    if total_traffic > 0:
        blocked_percentage = (metrics["blocked"] / total_traffic) * 100
    
    # Get top blocked ports with service names
    port_services = get_port_services()
    top_blocked_ports = [
        {"port": port, "service": port_services.get(port, "Unknown"), "count": count}
        for port, count in metrics["blocked_ports"].most_common(10)
    ]
    
    # Get top blocked IPs
    top_blocked_ips = [
        {"ip": ip, "count": count}
        for ip, count in metrics["blocked_ips"].most_common(10)
    ]
    
    # Get top traffic sources
    top_traffic_sources = [
        {"ip": ip, "count": count}
        for ip, count in metrics["traffic_sources"].most_common(10)
    ]
    
    # Create summary
    summary = {
        "total_entries": total_entries,
        "allowed_connections": metrics["allowed"],
        "blocked_connections": metrics["blocked"],
        "disconnected_connections": metrics["disconnected"],
        "nat_operations": metrics["nat"],
        "unique_ips": len(metrics["unique_ips"]),
        "blocked_percentage": round(blocked_percentage, 2),
        "firewall_type": parser_name
    }
    
    # Create final result structure
    result = {
        "firewall_analysis": {
            "summary": summary,
            "top_blocked_ports": top_blocked_ports,
            "top_blocked_ips": top_blocked_ips,
            "top_traffic_sources": top_traffic_sources,
        },
        "summary": {
            "total_entries": total_entries,
            "error_rate": f"{(error_count / max(1, total_entries) * 100):.1f}%",
            "unique_ips": len(metrics["unique_ips"]),
        },
        "errors": {
            "count": error_count,
            "messages": error_messages
        }
    }
    
    logging.info(f"Firewall analysis complete: {len(all_entries)} entries, {error_count} errors")
    return result

def get_port_services():
    """Get dictionary of common ports and their services"""
    return {
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

@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get task status and results"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    logging.info(f"Getting status for task {task_id}")
    logging.info(f"Task data: {tasks[task_id]}")
    
    return tasks[task_id]


@app.get("/parsers")
async def list_parsers():
    """List available parsers"""
    return {
        name: parser_class.__doc__ or "No description"
        for name, parser_class in analyzer.parser_factory._parsers.items()
    }


# Get the current directory
STATIC_DIR = Path(__file__).parent / "static"

# Add route for static files (frontend)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)