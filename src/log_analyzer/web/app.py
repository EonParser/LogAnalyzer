import asyncio
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
from pydantic import BaseModel

from ..core.analyzer import LogAnalyzer
from ..parsers.apache import ApacheLogParser
from ..parsers.base import ParserFactory, SimpleLineParser
from ..parsers.custom import IncidentLogParser
from ..parsers.nginx import NginxAccessLogParser
from ..processors.pipeline import Pipeline
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


# Create analyzer with SimpleLineParser
def create_analyzer():
    """Create and configure analyzer instance"""
    parser_factory = ParserFactory()
    parser_factory.register_parser("simple", SimpleLineParser)
    return LogAnalyzer(parser_factory=parser_factory)


# Use the create_analyzer function
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


async def process_logs(
    task_id: str,
    saved_files: List[dict],
    parser_name: Optional[str],
    filters: Optional[List[str]],
):
    """Process logs in background"""
    try:
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
                # Analyze the saved file
                file_results = analyzer.analyze_file(
                    file_info["path"], parser_name=parser_name, pipeline=pipeline
                )

                results.append(
                    {"filename": file_info["filename"], "results": file_results}
                )

            finally:
                # Clean up the temp file
                try:
                    file_info["path"].unlink()
                except:
                    pass

        # Update task with results
        tasks[task_id].update(
            {"status": "completed", "completed_at": datetime.now(), "results": results}
        )

    except Exception as e:
        logging.exception("Error processing logs")
        tasks[task_id].update(
            {"status": "failed", "completed_at": datetime.now(), "error": str(e)}
        )
    finally:
        # Clean up any remaining temp files
        for file_info in saved_files:
            try:
                if file_info["path"].exists():
                    file_info["path"].unlink()
            except:
                pass


@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get task status and results"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")

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
