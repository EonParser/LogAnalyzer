import asyncio
from collections import defaultdict
import json
import logging
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from log_analyzer.parsers.syslog import SyslogParser
from pydantic import BaseModel

from ..core.analyzer import LogAnalyzer
from ..parsers.apache import ApacheErrorLogParser, ApacheLogParser
from ..parsers.base import ParserFactory, SimpleLineParser
from ..parsers.custom import IncidentLogParser
from ..parsers.nginx import NginxAccessLogParser, NginxErrorLogParser
from ..processors.pipeline import FilterStep, Pipeline
from ..processors.transformers import TransformerFactory

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
analyzer = LogAnalyzer()
analyzer.parser_factory.register_parser("apache", ApacheLogParser)
analyzer.parser_factory.register_parser("nginx", NginxAccessLogParser)

# Store analysis tasks
tasks: Dict[str, Dict[str, Any]] = {}


def create_analyzer():
    """Create and configure analyzer instance"""
    parser_factory = ParserFactory()
    
    # Register parser classes for different log formats
    parser_factory.register_parser("apache_access", ApacheLogParser)  # For access logs
    parser_factory.register_parser("apache_error", ApacheErrorLogParser)  # For error logs
    parser_factory.register_parser("nginx_access", NginxAccessLogParser)
    parser_factory.register_parser("nginx_error", NginxErrorLogParser)
    parser_factory.register_parser("syslog", SyslogParser)
    parser_factory.register_parser("simple", SimpleLineParser)  # Fallback parser
    
    return LogAnalyzer(parser_factory=parser_factory)

# Initialize the analyzer
analyzer = create_analyzer()


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
):
    try:
        task_id = str(uuid.uuid4())
        saved_files = []

        # Save uploaded files
        for file in files:
            temp_dir = Path(tempfile.gettempdir()) / "log_analyzer"
            temp_dir.mkdir(exist_ok=True)
            temp_path = temp_dir / f"{task_id}_{file.filename}"

            content = await file.read()
            temp_path.write_bytes(content)

            saved_files.append({"path": temp_path, "filename": file.filename})

        tasks[task_id] = {
            "status": "pending",
            "created_at": datetime.now(),
            "files": [f["filename"] for f in saved_files],
            "results": None,
            "error": None,
            "temp_files": saved_files,
        }

        background_tasks.add_task(
            process_logs,
            task_id,
            saved_files,
            parser or "simple",  # Use simple parser by default
            filters.split(",") if filters else None,
        )

        return {
            "task_id": task_id,
            "status": "pending",
            "created_at": tasks[task_id]["created_at"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def process_logs(task_id: str, saved_files: List[dict], parser_name: Optional[str], filters: Optional[List[str]]):
    """Process logs in background"""
    try:
        logging.info(f"Starting processing task {task_id}")
        tasks[task_id]["status"] = "processing"

        # Create pipeline if needed
        pipeline = None
        if filters:
            pipeline = Pipeline()
            for filter_expr in filters:
                pipeline.add_step(
                    FilterStep("custom_filter", eval(f"lambda entry: {filter_expr}"))
                )

        # Process each file
        results = []
        for file_info in saved_files:
            try:
                logging.info(f"Processing file {file_info['filename']}")
                
                try:
                    # Analyze the saved file
                    file_results = analyzer.analyze_file(
                        file_info["path"], 
                        parser_name=parser_name, 
                        pipeline=pipeline
                    )
                    
                    logging.info(f"Analysis complete for {file_info['filename']}")
                    results.append({
                        "filename": file_info["filename"],
                        "results": file_results
                    })
                except ValueError as e:
                    raise ValueError(f"Error analyzing {file_info['filename']}: {str(e)}")

            finally:
                # Clean up temp file
                try:
                    file_info["path"].unlink()
                except:
                    pass

        if not results:
            raise ValueError("No files were successfully processed")

        # The metrics are already properly structured in our results
        # We just need to combine them from multiple files if needed
        combined_results = {
            'summary': results[0]['results']['summary'],  # Use first file's summary as base
            'http_analysis': results[0]['results']['http_analysis'],
            'error_analysis': results[0]['results']['error_analysis'],
            'security_analysis': results[0]['results']['security_analysis'],
            'performance_metrics': results[0]['results']['performance_metrics'],
            'time_analysis': results[0]['results']['time_analysis']
        }

        # If there are multiple files, aggregate the metrics
        if len(results) > 1:
            combined_results['summary'].update({
                'total_entries': sum(r['results']['summary']['total_entries'] for r in results),
                'error_rate': f"{sum(float(r['results']['summary']['error_rate'].rstrip('%')) for r in results)/len(results):.1f}%",
                'average_response_time': f"{sum(float(r['results']['summary']['average_response_time'].rstrip('ms')) for r in results)/len(results):.0f}ms",
                'unique_ips': sum(r['results']['summary']['unique_ips'] for r in results)
            })

        tasks[task_id].update({
            "status": "completed",
            "completed_at": datetime.now(),
            "results": combined_results
        })
        logging.info(f"Task {task_id} completed successfully")

    except Exception as e:
        logging.exception("Error processing logs")
        tasks[task_id].update({
            "status": "failed",
            "completed_at": datetime.now(),
            "error": str(e)
        })

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
