import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Union, Dict, Any
import json
import threading
from datetime import datetime
import queue
import atexit
from contextlib import contextmanager
import time

class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def __init__(
        self,
        timestamp_format: str = "%Y-%m-%d %H:%M:%S.%f",
        **kwargs
    ):
        """Initialize formatter.
        
        Args:
            timestamp_format: Timestamp format string
            **kwargs: Additional fields to include
        """
        super().__init__()
        self.timestamp_format = timestamp_format
        self.additional_fields = kwargs
        
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted string
        """
        # Basic record attributes
        data = {
            'timestamp': datetime.fromtimestamp(record.created).strftime(
                self.timestamp_format
            ),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            data['exception'] = self.formatException(record.exc_info)
            
        # Add stack info if present
        if record.stack_info:
            data['stack_info'] = self.formatStack(record.stack_info)
            
        # Add additional fields
        data.update(self.additional_fields)
        
        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            data.update(record.extra_fields)
            
        return json.dumps(data)

class AsyncHandler(logging.Handler):
    """Asynchronous log handler using queue"""
    
    def __init__(
        self,
        handler: logging.Handler,
        queue_size: int = 1000
    ):
        """Initialize handler.
        
        Args:
            handler: Base handler to wrap
            queue_size: Maximum queue size
        """
        super().__init__()
        self.handler = handler
        self.queue = queue.Queue(maxsize=queue_size)
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()
        self._stop_event = threading.Event()
        atexit.register(self.close)
        
    def emit(self, record: logging.LogRecord) -> None:
        """Put record in queue.
        
        Args:
            record: Log record to handle
        """
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            sys.stderr.write("Logging queue is full, discarding message\n")
            
    def _process_queue(self) -> None:
        """Process records from queue"""
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                record = self.queue.get(timeout=0.1)
                self.handler.emit(record)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                import traceback
                sys.stderr.write(
                    f"Error processing log record: {traceback.format_exc()}\n"
                )
                
    def close(self) -> None:
        """Close handler and wait for queue to empty"""
        self._stop_event.set()
        self.thread.join()
        self.handler.close()
        super().close()

class ContextualFilter(logging.Filter):
    """Filter that adds contextual information to records"""
    
    def __init__(self):
        """Initialize filter"""
        super().__init__()
        self._context = threading.local()
        
    def filter(self, record: logging.LogRecord) -> bool:
        """Add context to record.
        
        Args:
            record: Log record to filter
            
        Returns:
            True to include record
        """
        context = getattr(self._context, 'value', {})
        if not hasattr(record, 'extra_fields'):
            record.extra_fields = {}
        record.extra_fields.update(context)
        return True
        
    @contextmanager
    def context(self, **kwargs):
        """Add temporary context.
        
        Args:
            **kwargs: Context values to add
        """
        old_context = getattr(self._context, 'value', {}).copy()
        self._context.value = old_context.copy()
        self._context.value.update(kwargs)
        try:
            yield
        finally:
            self._context.value = old_context

class MetricsHandler(logging.Handler):
    """Handler that collects logging metrics"""
    
    def __init__(self):
        """Initialize handler"""
        super().__init__()
        self.metrics = {
            'total_records': 0,
            'levels': {},
            'loggers': {},
            'start_time': time.time()
        }
        self._lock = threading.Lock()
        
    def emit(self, record: logging.LogRecord) -> None:
        """Update metrics with record.
        
        Args:
            record: Log record to handle
        """
        with self._lock:
            self.metrics['total_records'] += 1
            
            # Update level counts
            level = record.levelname
            self.metrics['levels'][level] = (
                self.metrics['levels'].get(level, 0) + 1
            )
            
            # Update logger counts
            logger = record.name
            self.metrics['loggers'][logger] = (
                self.metrics['loggers'].get(logger, 0) + 1
            )
            
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics.
        
        Returns:
            Dictionary of metrics
        """
        with self._lock:
            metrics = self.metrics.copy()
            metrics['duration'] = time.time() - metrics['start_time']
            return metrics

def setup_logging(
    level: Union[str, int] = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    json_format: bool = False,
    async_handlers: bool = True,
    include_metrics: bool = False,
    **kwargs
) -> None:
    """Set up logging configuration.
    
    Args:
        level: Log level
        log_file: Optional log file path
        json_format: Whether to use JSON formatting
        async_handlers: Whether to use async handlers
        include_metrics: Whether to include metrics handler
        **kwargs: Additional fields for JSON formatter
    """
    # Create handlers
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler()
    if json_format:
        console_handler.setFormatter(JsonFormatter(**kwargs))
    else:
        console_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            )
        )
    handlers.append(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        if json_format:
            file_handler.setFormatter(JsonFormatter(**kwargs))
        else:
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                )
            )
        handlers.append(file_handler)
    
    # Wrap handlers in async handler if requested
    if async_handlers:
        handlers = [AsyncHandler(h) for h in handlers]
    
    # Add metrics handler if requested
    metrics_handler = None
    if include_metrics:
        metrics_handler = MetricsHandler()
        handlers.append(metrics_handler)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add new handlers
    for handler in handlers:
        root_logger.addHandler(handler)
    
    # Add contextual filter
    context_filter = ContextualFilter()
    root_logger.addFilter(context_filter)
    
    return metrics_handler

@contextmanager
def log_duration(
    logger: Union[str, logging.Logger],
    message: str,
    level: int = logging.INFO
) -> None:
    """Log duration of code block.
    
    Args:
        logger: Logger name or instance
        message: Message template with {duration}
        level: Log level
    """
    if isinstance(logger, str):
        logger = logging.getLogger(logger)
        
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        logger.log(level, message.format(duration=f"{duration:.3f}s"))

if __name__ == '__main__':
    # Example usage
    setup_logging(
        level=logging.DEBUG,
        log_file='app.log',
        json_format=True,
        async_handlers=True,
        include_metrics=True,
        app_name='example'
    )
    
    logger = logging.getLogger(__name__)
    
    with log_duration(logger, "Operation took {duration}"):
        logger.info("Processing started")
        time.sleep(1)
        logger.debug("Intermediate step")
        time.sleep(1)
        logger.info("Processing completed")