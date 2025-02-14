# Log Analyzer API Documentation

## Core Components

### LogAnalyzer

The main class for analyzing log files.

```python
class LogAnalyzer:
    def __init__(self, parser_factory: Optional[ParserFactory] = None, max_workers: int = 4):
        """Initialize log analyzer.
        
        Args:
            parser_factory: Factory for creating log parsers
            max_workers: Maximum number of worker threads
        """
        pass

    def analyze_file(
        self, 
        file_path: Path,
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None
    ) -> Dict[str, Any]:
        """Analyze a single log file.
        
        Args:
            file_path: Path to log file
            parser_name: Name of parser to use, or None for auto-detect
            pipeline: Optional processing pipeline
            
        Returns:
            Dictionary of analysis results
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If no suitable parser found
        """
        pass

    def analyze_directory(
        self,
        directory: Path,
        pattern: str = "*.log*",
        parser_name: Optional[str] = None,
        pipeline: Optional[Pipeline] = None,
        max_workers: Optional[int] = None
    ) -> Dict[str, Any]:
        """Analyze all matching files in a directory.
        
        Args:
            directory: Directory to scan
            pattern: Glob pattern for matching files
            parser_name: Name of parser to use, or None for auto-detect
            pipeline: Optional processing pipeline
            max_workers: Maximum number of worker threads
            
        Returns:
            Combined analysis results
        """
        pass
```

### Parser Components

#### BaseParser

Abstract base class for all log parsers.

```python
class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single line of log text.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            LogEntry if successful, None if line should be skipped
            
        Raises:
            ParserError: If line cannot be parsed
        """
        pass
    
    @abstractmethod
    def supports_format(self, line: str) -> bool:
        """Check if this parser supports the given log format.
        
        Args:
            line: Sample log line to check
            
        Returns:
            True if this parser can handle the format
        """
        pass
```

#### LogEntry

Data class representing a parsed log entry.

```python
@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    source: str
    raw_data: str
    parsed_data: Dict[str, Any]
    metadata: Dict[str, Any]
```

### Processing Components

#### Pipeline

Processing pipeline for log entries.

```python
class Pipeline:
    def __init__(self):
        """Initialize empty pipeline."""
        pass

    def add_step(self, step: ProcessingStep) -> None:
        """Add a processing step to the pipeline."""
        pass

    def add_preprocessor(self, func: Callable[[LogEntry], None]) -> None:
        """Add a preprocessing function."""
        pass

    def add_postprocessor(self, func: Callable[[LogEntry], None]) -> None:
        """Add a postprocessing function."""
        pass

    def process(self, entry: LogEntry) -> Optional[LogEntry]:
        """Process a log entry through the pipeline."""
        pass
```

#### Processing Steps

##### FilterStep

```python
class FilterStep(ProcessingStep):
    def __init__(self, name: str, predicate: Callable[[LogEntry], bool]):
        """Initialize filter step.
        
        Args:
            name: Step name
            predicate: Function that returns True for entries to keep
        """
        pass
```

##### TransformStep

```python
class TransformStep(ProcessingStep):
    def __init__(self, name: str, transformer: Callable[[LogEntry], LogEntry]):
        """Initialize transform step.
        
        Args:
            name: Step name
            transformer: Function to transform entries
        """
        pass
```

##### EnrichmentStep

```python
class EnrichmentStep(ProcessingStep):
    def __init__(self, name: str, enricher: Callable[[LogEntry], dict]):
        """Initialize enrichment step.
        
        Args:
            name: Step name
            enricher: Function that returns data to add to entry
        """
        pass
```

### Transformer Components

#### LogTransformer

Collection of common log transformation functions.

```python
class LogTransformer:
    @staticmethod
    def normalize_timestamp(entry: LogEntry) -> LogEntry:
        """Convert timestamp to UTC and ISO format."""
        pass

    @staticmethod
    def normalize_level(entry: LogEntry) -> LogEntry:
        """Normalize log levels to standard format."""
        pass

    @staticmethod
    def mask_sensitive_data(entry: LogEntry, patterns: Dict[str, str]) -> LogEntry:
        """Mask sensitive data in log messages and parsed data."""
        pass

    @staticmethod
    def enrich_ip_data(entry: LogEntry) -> LogEntry:
        """Enrich log entry with IP address information."""
        pass

    @staticmethod
    def parse_user_agent(entry: LogEntry) -> LogEntry:
        """Parse user agent string into components."""
        pass
```

## Common Patterns

### Creating a Custom Parser

```python
from log_analyzer.parsers.base import BaseParser, LogEntry

class CustomParser(BaseParser):
    def supports_format(self, line: str) -> bool:
        return line.startswith("CUSTOM")
        
    def parse_line(self, line: str) -> Optional[LogEntry]:
        # Parse line and create LogEntry
        return LogEntry(...)
```

### Building a Processing Pipeline

```python
from log_analyzer.processors.pipeline import Pipeline, FilterStep, TransformStep
from log_analyzer.processors.transformers import TransformerFactory

# Create pipeline
pipeline = Pipeline()

# Add error filtering
pipeline.add_step(
    FilterStep(
        'error_filter',
        lambda e: e.level in {'ERROR', 'CRITICAL'}
    )
)

# Add transformation
pipeline.add_step(
    TransformStep(
        'enrich',
        TransformerFactory.create_standard_transformer()
    )
)

# Add custom processing
def custom_process(entry: LogEntry) -> LogEntry:
    # Custom processing logic
    return entry

pipeline.add_step(TransformStep('custom', custom_process))
```

### Analyzing Logs

```python
from log_analyzer.core.analyzer import LogAnalyzer
from pathlib import Path

# Initialize analyzer
analyzer = LogAnalyzer()

# Analyze single file
results = analyzer.analyze_file(
    Path('access.log'),
    parser_name='apache'
)

# Analyze directory
results = analyzer.analyze_directory(
    Path('logs'),
    pattern="*.log",
    max_workers=4
)
```

## Error Handling

The library uses custom exceptions for different error cases:

```python
class ParserError(Exception):
    """Raised when a log line cannot be parsed."""
    pass

class PipelineError(Exception):
    """Raised when pipeline processing fails."""
    pass
```

## Performance Tips

1. Use appropriate chunk sizes for file reading:
```python
analyzer = LogAnalyzer(chunk_size=16384)
```

2. Adjust worker count based on system:
```python
analyzer.analyze_directory(path, max_workers=cpu_count())
```

3. Use filtering early in pipeline:
```python
pipeline.add_step(FilterStep('early_filter', predicate))
pipeline.add_step(TransformStep('expensive_transform', transform))
```

4. Monitor memory usage:
```python
import psutil
process = psutil.Process()
memory_before = process.memory_info().rss
# ... process logs ...
memory_after = process.memory_info().rss
memory_used = memory_after - memory_before
```

## Configuration

The library supports configuration through environment variables:

- `LOG_ANALYZER_MAX_WORKERS`: Maximum number of worker threads
- `LOG_ANALYZER_CHUNK_SIZE`: File reading chunk size
- `LOG_ANALYZER_DEBUG`: Enable debug logging

## Examples

See the `examples/` directory for more detailed examples:

- `basic_usage.py`: Simple log analysis
- `custom_parser.py`: Creating custom parsers
- `pipeline_processing.py`: Advanced pipeline usage