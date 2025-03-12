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
from .enhanced_firewall_metrics import extract_firewall_metrics, classify_ip, get_service_name
from .log_processor import LogProcessor
from .field_detector import FieldDetector

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
    filter_fields: Optional[Dict[str, List[str]]] = None 


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
    filter_fields: Optional[str] = Form(None),
    log_type: Optional[str] = Form("standard"),
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

        # Parse filter_fields if provided
        parsed_filter_fields = None
        if filter_fields:
            try:
                parsed_filter_fields = json.loads(filter_fields)
                logging.info(f"Parsed filter fields: {parsed_filter_fields}")
            except json.JSONDecodeError:
                logging.error(f"Invalid filter fields JSON: {filter_fields}")

        tasks[task_id] = {
            "status": "pending",
            "created_at": datetime.now(),
            "files": [f["filename"] for f in saved_files],
            "results": None,
            "error": None,
            "temp_files": saved_files,
            "log_type": log_type,  # Store log_type
            "filter_fields": parsed_filter_fields,  # Store filter_fields
        }

        # Choose default parser based on log type
        default_parser = "firewall" if log_type == "firewall" else "simple"
        
        background_tasks.add_task(
            process_logs,
            task_id,
            saved_files,
            parser or default_parser,
            filters.split(",") if filters else None,
            parsed_filter_fields,  # Pass filter_fields to process_logs
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
    filter_fields: Optional[Dict[str, List[str]]] = None,
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

            # Add field-based filters
            if filter_fields:
                logging.info(f"Applying field filters: {filter_fields}")
                for field_name, values in filter_fields.items():
                    try:
                        # Create a lambda function that checks if the field value is in the list
                        filter_func = eval(
                            f"lambda e: (hasattr(e, 'parsed_data') and "
                            f"e.parsed_data.get('{field_name}') in {values})"
                        )
                        pipeline.add_step(FilterStep(f"field_filter_{field_name}", filter_func))
                    except Exception as field_filter_err:
                        logging.warning(f"Failed to create filter for field '{field_name}': {str(field_filter_err)}")

            # Add different transformers based on log type
            if log_type == "firewall":
                pipeline.add_step(TransformerFactory.create_security_transformer())
                logging.info(f"Using security transformer for firewall logs")
            else:
                pipeline.add_step(TransformerFactory.create_standard_transformer())

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
    """Process firewall log files and extract enhanced firewall-specific metrics
    
    Args:
        saved_files: List of file info dictionaries
        parser_name: Name of parser to use
        pipeline: Processing pipeline
        
    Returns:
        Dictionary with enhanced firewall analysis results
    """
    from collections import Counter, defaultdict
    import traceback
    
    # Import enhanced firewall metrics functions
    from .enhanced_firewall_metrics import extract_firewall_metrics, classify_ip, get_service_name

    logging.info(f"Starting enhanced firewall log analysis with parser: {parser_name}")
    
    all_entries = []
    total_entries = 0
    error_count = 0
    error_messages = []
    
    # Initialize combined metrics structure
    combined_metrics = {
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
                # Ensure pipeline is properly configured
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
                
                # Use enhanced metrics extraction
                file_metrics = extract_firewall_metrics(results)
                
                # Merge with combined metrics
                # Numeric counters
                combined_metrics["allowed"] += file_metrics["allowed"]
                combined_metrics["blocked"] += file_metrics["blocked"]
                combined_metrics["disconnected"] += file_metrics["disconnected"]
                combined_metrics["nat"] += file_metrics["nat"] 
                combined_metrics["port_scan_attempts"] += file_metrics["port_scan_attempts"]
                combined_metrics["brute_force_attempts"] += file_metrics["brute_force_attempts"]
                combined_metrics["dos_attempts"] += file_metrics["dos_attempts"]
                
                # Merge sets
                combined_metrics["unique_ips"].update(file_metrics["unique_ips"])
                combined_metrics["suspicious_ips"].update(file_metrics["suspicious_ips"])
                
                # Merge counters
                for field in ["blocked_ips", "traffic_sources", "traffic_destinations", 
                            "blocked_ports", "target_ports", "source_ports", 
                            "protocols", "blocked_protocols", "interfaces", 
                            "interface_blocks", "rules_triggered", "block_reasons"]:
                    if field in file_metrics and file_metrics[field]:
                        for key, count in file_metrics[field].items():
                            combined_metrics[field][key] += count
                
                # Merge hourly distributions
                for hour, count in file_metrics["hourly_traffic"].items():
                    combined_metrics["hourly_traffic"][hour] += count
                for hour, count in file_metrics["hourly_blocks"].items():
                    combined_metrics["hourly_blocks"][hour] += count
                
                # Track total entries
                entries = results.get("entries", [])
                total_entries += len(entries)
                all_entries.extend(entries)
                
                # Log metrics for this file
                logging.info(f"File metrics for {filename}:")
                logging.info(f"  Allowed: {file_metrics['allowed']}")
                logging.info(f"  Blocked: {file_metrics['blocked']}")
                logging.info(f"  Unique IPs: {len(file_metrics['unique_ips'])}")
                logging.info(f"  Suspicious IPs: {len(file_metrics['suspicious_ips'])}")
                
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
    
    # Log final metrics summary
    logging.info(f"Enhanced firewall analysis summary:")
    logging.info(f"  Total entries: {total_entries}")
    logging.info(f"  Allowed connections: {combined_metrics['allowed']}")
    logging.info(f"  Blocked connections: {combined_metrics['blocked']}")
    logging.info(f"  Unique IPs: {len(combined_metrics['unique_ips'])}")
    logging.info(f"  Suspicious IPs: {len(combined_metrics['suspicious_ips'])}")
    logging.info(f"  Port scan attempts: {combined_metrics['port_scan_attempts']}")
    logging.info(f"  Brute force attempts: {combined_metrics['brute_force_attempts']}")
    logging.info(f"  DoS attempts: {combined_metrics['dos_attempts']}")
    
    # Calculate blocked percentage
    total_traffic = combined_metrics["allowed"] + combined_metrics["blocked"]
    blocked_percentage = 0
    if total_traffic > 0:
        blocked_percentage = (combined_metrics["blocked"] / total_traffic) * 100
    
    # Create enhanced results structure
    # Get top blocked ports with service names & percentages
    top_blocked_ports = [
        {"port": port, 
         "service": get_service_name(port), 
         "count": count,
         "percentage": (count / combined_metrics["blocked"] * 100) if combined_metrics["blocked"] > 0 else 0}
        for port, count in combined_metrics["blocked_ports"].most_common(10)
    ]
    
    # Get top blocked IPs with type classification
    top_blocked_ips = [
        {"ip": ip, 
         "count": count,
         "type": classify_ip(ip)}
        for ip, count in combined_metrics["blocked_ips"].most_common(10)
    ]
    
    # Get top traffic sources with type classification
    top_traffic_sources = [
        {"ip": ip, 
         "count": count,
         "type": classify_ip(ip)}
        for ip, count in combined_metrics["traffic_sources"].most_common(10)
    ]
    
    # Get top attacked services (same as blocked ports but with service focus)
    top_attacked_services = [
        {"service": get_service_name(port), 
         "port": port, 
         "count": count,
         "percentage": (count / combined_metrics["blocked"] * 100) if combined_metrics["blocked"] > 0 else 0}
        for port, count in combined_metrics["blocked_ports"].most_common(10)
    ]
    
    # Get top protocols
    top_protocols = [
        {"protocol": protocol, "count": count}
        for protocol, count in combined_metrics["protocols"].most_common(5)
    ]
    
    # Get top block reasons
    top_block_reasons = [
        {"reason": reason if reason else "Unknown", "count": count}
        for reason, count in combined_metrics["block_reasons"].most_common(5)
    ]
    
    # Create summary
    summary = {
        "total_entries": total_entries,
        "allowed_connections": combined_metrics["allowed"],
        "blocked_connections": combined_metrics["blocked"],
        "disconnected_connections": combined_metrics["disconnected"],
        "nat_operations": combined_metrics["nat"],
        "unique_ips": len(combined_metrics["unique_ips"]),
        "blocked_percentage": round(blocked_percentage, 2),
        "firewall_type": parser_name
    }
    
    # Create final enhanced result structure
    result = {
        "firewall_analysis": {
            "summary": summary,
            "top_blocked_ports": top_blocked_ports,
            "top_blocked_ips": top_blocked_ips,
            "top_traffic_sources": top_traffic_sources,
            "top_attacked_services": top_attacked_services,
            "top_protocols": top_protocols,
            "top_block_reasons": top_block_reasons,
            "hourly_distribution": {
                "traffic": dict(combined_metrics["hourly_traffic"]),
                "blocks": dict(combined_metrics["hourly_blocks"])
            },
            "attack_summary": {
                "port_scan_attempts": combined_metrics["port_scan_attempts"],
                "brute_force_attempts": combined_metrics["brute_force_attempts"],
                "dos_attempts": combined_metrics["dos_attempts"],
                "suspicious_ips_count": len(combined_metrics["suspicious_ips"]),
                "suspicious_ips": list(combined_metrics["suspicious_ips"])
            }
        },
        "summary": {
            "total_entries": total_entries,
            "error_rate": f"{(error_count / max(1, total_entries) * 100):.1f}%",
            "unique_ips": len(combined_metrics["unique_ips"]),
        },
        "errors": {
            "count": error_count,
            "messages": error_messages
        }
    }
    
    logging.info(f"Enhanced firewall analysis complete: {len(all_entries)} entries, {error_count} errors")
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