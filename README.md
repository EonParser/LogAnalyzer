# Log Analyzer Documentation

## Project Overview
The Log Analyzer is a production-grade tool designed to analyze various types of log files efficiently. It features both a web interface and CLI capabilities, supporting multiple log formats and offering real-time analysis.

## Architecture

### Core Components

1. **Log Parser Framework**
```python
class LogAnalyzer:
    def __init__(self, parser_factory: Optional[ParserFactory] = None):
        self.parser_factory = parser_factory or ParserFactory()
        self.reader = LogReader()
```
- Central component that coordinates parsing and analysis
- Uses Factory pattern for extensible parser management
- Efficient file reading with streaming capabilities

2. **Parser System**
```python
class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        pass
```
- Abstract base class for all parsers
- Supports multiple formats (Apache, Nginx, Syslog, Custom)
- Easy to extend for new log formats

3. **Processing Pipeline**
```python
class Pipeline:
    def __init__(self):
        self.steps = []
        self._preprocessors = []
        self._postprocessors = []
```
- Modular processing system
- Supports filtering, transformation, and enrichment
- Can be customized per analysis

### Web Interface

1. **FastAPI Backend**
```python
@app.post("/analyze")
async def analyze_logs(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    parser: Optional[str] = Form(None),
    filters: Optional[str] = Form(None)
):
```
- RESTful API endpoints
- Asynchronous processing
- Background task handling

2. **Frontend**
```html
<div class="container mx-auto px-4 py-8">
    <!-- Upload Form -->
    <div class="bg-white rounded-lg shadow p-6 mb-8">
        <h2 class="text-xl font-semibold mb-4">Analyze Logs</h2>
        <form id="uploadForm">...</form>
    </div>
</div>
```
- Modern, responsive UI using Tailwind CSS
- Real-time updates
- Interactive results display

## Key Features

### 1. Multi-format Support
- Auto-detection of log formats
- Built-in parsers for common formats
- Custom parser support for specialized formats

### 2. Performance Optimization
```python
def read_lines(self, file_path: Union[str, Path]) -> Iterator[str]:
    with open(path, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
```
- Memory-mapped file reading
- Streaming processing
- Concurrent analysis for multiple files

### 3. Error Handling
```python
try:
    entry = parser.parse_line(line)
    if entry:
        self.metrics.process_entry(entry)
except Exception as e:
    self.metrics.record_error(str(e))
```
- Robust error detection
- Detailed error reporting
- Graceful failure handling

### 4. Extensibility
```python
class CustomParser(BaseParser):
    def supports_format(self, line: str) -> bool:
        return True  # Custom logic here
```
- Plugin architecture for parsers
- Custom pipeline processors
- Configurable metrics collection

## Usage Examples

### Web Interface
1. Upload logs:
```javascript
document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData();
    // File handling...
});
```

2. View results:
```javascript
function displayResults(container, results) {
    const content = results.map(file => `
        <div class="border rounded-lg p-4">
            <h3>${file.filename}</h3>
            // Result display...
        </div>
    `);
}
```

### CLI Usage
```bash
loganalyzer analyze access.log --parser apache
loganalyzer scan /var/log --pattern "*.log"
```

## Configuration

### Environment Variables
```python
DEFAULT_CONFIG = {
    'parsing': {
        'chunk_size': 8192,
        'max_line_length': 1048576
    },
    'processing': {
        'max_workers': 4
    }
}
```

### File-based Configuration
```json
{
    "parsing": {
        "chunk_size": 16384
    }
}
```

## Project Structure
```
log-analyzer/
├── src/
│   └── log_analyzer/
│       ├── core/         # Core functionality
│       ├── parsers/      # Log parsers
│       ├── processors/   # Processing pipeline
│       ├── utils/        # Utilities
│       ├── web/          # Web interface
│       └── cli.py        # CLI interface
├── tests/                # Test suite
├── docs/                 # Documentation
└── examples/            # Example usage
```

## Development Workflow

1. **Setup**
```bash
python -m venv venv
source venv/bin/activate
pip install -e .[dev]
```

2. **Testing**
```bash
pytest --cov=log_analyzer
```

3. **Running**
```bash
uvicorn log_analyzer.web.app:app --reload
```

## Future Enhancements

1. **Visualization**
- Add charts and graphs
- Timeline views
- Pattern detection visualization

2. **Analysis Features**
- Machine learning integration
- Anomaly detection
- Pattern matching

3. **Performance**
- Distributed processing
- Caching layer
- Stream processing

4. **Integration**
- Export capabilities
- API integrations
- Alert system
