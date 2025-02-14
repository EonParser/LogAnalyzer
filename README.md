# Log Analyzer

A powerful, production-grade log analysis tool with both CLI and web interfaces.

## Features

- **Multi-format Support**: Parse Apache, Nginx, Syslog, and custom log formats
- **Efficient Processing**: Handle large log files with streaming and concurrent processing
- **Flexible Pipeline**: Configurable processing steps for filtering and transformation
- **Multiple Interfaces**: 
  - CLI for command-line operations
  - Web interface for visual analysis
  - API for integration
- **Rich Analysis**: 
  - Pattern detection
  - Error analysis
  - Performance metrics
  - Custom filtering

## Installation

```bash
pip install log-analyzer
```

## Quick Start

### Command Line Usage

```bash
# Analyze a single log file
loganalyzer analyze access.log

# Analyze multiple files with filtering
loganalyzer analyze --parser apache --filter "level=='ERROR'" *.log

# Scan directory for log files
loganalyzer scan /var/log

# Follow log file in real-time
loganalyzer tail -f /var/log/apache2/access.log
```

### Web Interface

```bash
# Start web server
loganalyzer-web

# Open http://localhost:8000 in your browser
```

### Python API

```python
from log_analyzer import LogAnalyzer
from log_analyzer.processors.pipeline import Pipeline

# Initialize analyzer
analyzer = LogAnalyzer()

# Create processing pipeline
pipeline = Pipeline()
pipeline.add_step(lambda entry: entry.level == 'ERROR')

# Analyze logs
results = analyzer.analyze_file('access.log', pipeline=pipeline)
```

## Configuration

Configuration can be provided via:
- Config file (JSON/YAML)
- Environment variables
- Command line options

Example config.json:
```json
{
    "parsing": {
        "chunk_size": 8192,
        "max_line_length": 1048576
    },
    "processing": {
        "max_workers": 4,
        "batch_size": 1000
    }
}
```

## Architecture

The system consists of several key components:

1. **Core Parser Framework**
   - Extensible parser interface
   - Streaming file processing
   - Memory-efficient handling

2. **Processing Pipeline**
   - Configurable processing steps
   - Filter and transform operations
   - Concurrent processing

3. **User Interfaces**
   - CLI with rich output
   - Web interface with real-time updates
   - RESTful API

4. **Utilities**
   - File handling
   - String processing
   - Configuration management

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=log_analyzer

# Run specific test file
pytest tests/test_parsers/test_apache.py
```

### Project Structure

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

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Adding New Parser

1. Create new parser class:
```python
from log_analyzer.parsers.base import BaseParser

class CustomParser(BaseParser):
    def supports_format(self, line: str) -> bool:
        return line.startswith('CUSTOM')
        
    def parse_line(self, line: str) -> Optional[LogEntry]:
        # Parse line
        return LogEntry(...)
```

2. Register parser:
```python
analyzer.parser_factory.register_parser('custom', CustomParser)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.