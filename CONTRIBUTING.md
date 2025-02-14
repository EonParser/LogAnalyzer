# Contributing to Log Analyzer

We love your input! We want to make contributing to Log Analyzer as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Development Setup

1. Clone your fork:
```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e .[dev]
```

4. Set up pre-commit hooks:
```bash
pre-commit install
```

## Code Style

We use several tools to maintain code quality:

- `black` for code formatting
- `isort` for import sorting
- `mypy` for type checking
- `pylint` for code analysis

Configuration for these tools is in `pyproject.toml`.

### Type Hints

We use type hints throughout the codebase. Always add type hints to function arguments and return values:

```python
from typing import Optional, Dict, Any

def process_data(input_data: Dict[str, Any]) -> Optional[str]:
    """Process input data and return result."""
    pass
```

### Documentation

- Use docstrings for all public modules, functions, classes, and methods
- Follow Google style for docstrings
- Include examples in docstrings where appropriate

Example:
```python
def parse_line(self, line: str) -> Optional[LogEntry]:
    """Parse a single log line into structured data.
    
    Args:
        line: Raw log line to parse
        
    Returns:
        LogEntry if successful, None if line should be skipped
        
    Raises:
        ParserError: If line cannot be parsed
        
    Example:
        >>> parser = CustomParser()
        >>> entry = parser.parse_line("INFO: Test message")
        >>> print(entry.level)
        'INFO'
    """
    pass
```

## Testing

We use pytest for testing. Tests should be:

- Comprehensive: Test both success and failure cases
- Fast: No unnecessary computation or I/O
- Independent: No dependencies between tests
- Clear: Test names should describe what's being tested

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=log_analyzer

# Run specific test file
pytest tests/test_parsers/test_apache.py

# Run performance tests
pytest tests/test_performance.py
```

### Writing Tests

Example test structure:
```python
import pytest
from log_analyzer.parsers.base import LogEntry

@pytest.fixture
def sample_entry():
    """Create sample log entry for testing."""
    return LogEntry(...)

def test_feature_success(sample_entry):
    """Test successful case."""
    result = process_entry(sample_entry)
    assert result.is_valid

def test_feature_failure(sample_entry):
    """Test failure case."""
    with pytest.raises(ValueError):
        process_entry(invalid_entry)
```

## Pull Request Process

1. Update the README.md with details of changes to the interface
2. Update the version number in `pyproject.toml`
3. Add your changes to the CHANGELOG.md
4. The PR will be merged once you have the sign-off of at least one maintainer

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Type hints added/updated
- [ ] Code formatting checked
- [ ] Import order checked
- [ ] Type checking passed
- [ ] Changelog updated
- [ ] Version bumped

## Bug Reports

Report bugs using GitHub's [issue tracker](https://github.com/yourusername/log-analyzer/issues)

Good bug reports include:

- Quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening)

## Feature Requests

Feature requests are welcome! Please provide:

- Clear description of the feature
- Use cases
- Benefits and potential drawbacks
- Example usage if possible

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## References

- Python typing: [docs.python.org/3/library/typing.html](https://docs.python.org/3/library/typing.html)
- pytest: [docs.pytest.org](https://docs.pytest.org)
- Black: [black.readthedocs.io](https://black.readthedocs.io)
- mypy: [mypy.readthedocs.io](https://mypy.readthedocs.io)