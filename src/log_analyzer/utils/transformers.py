def normalize_timestamp(entry: LogEntry) -> LogEntry:
    """Convert timestamp to UTC"""
    if entry.timestamp.tzinfo is None:
        entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)
    return entry