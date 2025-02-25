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
analyzer = LogAnalyzer()
analyzer.parser_factory.register_parser("apache", ApacheLogParser)
analyzer.parser_factory.register_parser("nginx", NginxAccessLogParser)

# Store analysis tasks
tasks: Dict[str, Dict[str, Any]] = {}

def create_analyzer():
    """Create and configure analyzer instance"""
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
    """Process uploaded log files"""
    try:
        logging.info(f"Starting processing task {task_id}")
        tasks[task_id]["status"] = "processing"

        try:
            # Create pipeline with filters if specified
            pipeline = None
            if filters and len(filters) > 0:
                pipeline = Pipeline()
                for i, filter_expr in enumerate(filters):
                    try:
                        pipeline.add_step(FilterStep(f"filter_{i}", eval(f"lambda e: {filter_expr}")))
                    except Exception as filter_err:
                        logging.warning(f"Failed to create filter from expression '{filter_expr}': {str(filter_err)}")

            # Process logs using the processor
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
            
            logging.info(
                f"Task {task_id} completed successfully. "
                f"Processed {combined_results['summary']['total_entries']} entries"
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
