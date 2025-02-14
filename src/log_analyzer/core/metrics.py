from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List

from ..parsers.base import LogEntry


class MetricsCollector:
    """Collects and aggregates metrics from log entries"""

    def __init__(self):
        """Initialize metrics collector"""
        self.reset()

    def reset(self) -> None:
        """Reset all metrics to initial state"""
        self._total_entries = 0
        self._error_count = 0
        self._errors: List[str] = []
        self._level_counts: Dict[str, int] = defaultdict(int)
        self._hourly_counts: Dict[str, int] = defaultdict(int)
        self._source_counts: Dict[str, int] = defaultdict(int)
        self._first_timestamp: datetime | None = None
        self._last_timestamp: datetime | None = None

    def process_entry(self, entry: LogEntry) -> None:
        """Process a log entry and update metrics

        Args:
            entry: Log entry to process
        """
        self._total_entries += 1

        # Update level counts
        self._level_counts[entry.level] += 1

        # Update source counts
        self._source_counts[entry.source] += 1

        # Update timestamp info
        hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
        self._hourly_counts[hour_key] += 1

        if not self._first_timestamp or entry.timestamp < self._first_timestamp:
            self._first_timestamp = entry.timestamp

        if not self._last_timestamp or entry.timestamp > self._last_timestamp:
            self._last_timestamp = entry.timestamp

    def record_error(self, error: str) -> None:
        """Record a processing error

        Args:
            error: Error message to record
        """
        self._error_count += 1
        self._errors.append(error)

    def get_results(self) -> Dict[str, Any]:
        """Get current metrics results

        Returns:
            Dictionary containing all collected metrics
        """
        duration = (
            (self._last_timestamp - self._first_timestamp).total_seconds()
            if self._first_timestamp and self._last_timestamp
            else 0
        )

        return {
            "total_entries": self._total_entries,
            "errors": {
                "count": self._error_count,
                "messages": self._errors[-100:],  # Keep last 100 errors
            },
            "level_distribution": dict(self._level_counts),
            "source_distribution": dict(self._source_counts),
            "hourly_distribution": dict(self._hourly_counts),
            "time_range": {
                "start": self._first_timestamp,
                "end": self._last_timestamp,
                "duration_seconds": duration,
            },
            "entries_per_second": (
                self._total_entries / duration if duration > 0 else 0
            ),
        }
