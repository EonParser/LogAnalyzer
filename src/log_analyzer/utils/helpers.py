import gzip
import ipaddress
import json
import logging
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class LogAnalyzerError(Exception):
    """Base exception for log analyzer errors"""

    pass


def parse_timestamp(timestamp_str: str, formats: List[str]) -> datetime:
    """Parse timestamp string using multiple formats.

    Args:
        timestamp_str: Timestamp string to parse
        formats: List of format strings to try

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If timestamp cannot be parsed with any format
    """
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unable to parse timestamp: {timestamp_str}")


def ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is in UTC.

    Args:
        dt: Datetime object

    Returns:
        Datetime object in UTC
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to integer.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Converted integer or default value
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def get_ip_info(ip_str: str) -> Dict[str, Any]:
    """Get information about an IP address.

    Args:
        ip_str: IP address string

    Returns:
        Dictionary containing IP information

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return {
            "version": ip.version,
            "is_private": ip.is_private,
            "is_global": ip.is_global,
            "is_multicast": ip.is_multicast,
            "is_loopback": ip.is_loopback,
            "network": str(ip.network) if hasattr(ip, "network") else None,
        }
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip_str}") from e


def parse_user_agent(ua_string: str) -> Dict[str, Any]:
    """Parse user agent string.

    Args:
        ua_string: User agent string

    Returns:
        Dictionary containing parsed information
    """
    patterns = {
        "browser": [
            (r"Chrome/(\S+)", "Chrome"),
            (r"Firefox/(\S+)", "Firefox"),
            (r"Safari/(\S+)", "Safari"),
            (r"MSIE (\S+)", "Internet Explorer"),
            (r"Edg/(\S+)", "Edge"),
        ],
        "os": [
            (r"Windows NT (\S+)", "Windows"),
            (r"Macintosh.*OS X (\S+)", "MacOS"),
            (r"Linux", "Linux"),
            (r"Android (\S+)", "Android"),
            (r"iOS (\S+)", "iOS"),
        ],
        "device": [
            (r"Mobile", "Mobile"),
            (r"Tablet", "Tablet"),
            (r"Desktop", "Desktop"),
        ],
    }

    result = {
        "browser": {"name": "Unknown", "version": None},
        "os": {"name": "Unknown", "version": None},
        "device_type": "Unknown",
        "is_mobile": bool(re.search(r"Mobile|Android|iOS|iPhone|iPad", ua_string)),
    }

    # Detect browser
    for pattern, name in patterns["browser"]:
        match = re.search(pattern, ua_string)
        if match:
            result["browser"] = {
                "name": name,
                "version": match.group(1) if match.groups() else None,
            }
            break

    # Detect OS
    for pattern, name in patterns["os"]:
        match = re.search(pattern, ua_string)
        if match:
            result["os"] = {
                "name": name,
                "version": match.group(1) if match.groups() else None,
            }
            break

    # Detect device type
    for pattern, device_type in patterns["device"]:
        if re.search(pattern, ua_string):
            result["device_type"] = device_type
            break

    return result


@contextmanager
def timer(name: str = None):
    """Context manager for timing code blocks.

    Args:
        name: Optional name for the timer
    """
    start = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start
    if name:
        logger.info(f"{name} took {elapsed:.2f} seconds")
    else:
        logger.info(f"Operation took {elapsed:.2f} seconds")


def estimate_line_count(file_path: Path) -> int:
    """Estimate number of lines in a file.

    Args:
        file_path: Path to file

    Returns:
        Estimated line count
    """
    chunk_size = 1024 * 1024  # 1MB
    with open(file_path, "rb") as f:
        # Read first chunk
        first_chunk = f.read(chunk_size)
        if not first_chunk:
            return 0

        # Count newlines in first chunk
        newlines_per_chunk = first_chunk.count(b"\n")

        # Get file size
        f.seek(0, 2)
        file_size = f.tell()

        # Estimate total lines
        estimated_lines = int((file_size / chunk_size) * newlines_per_chunk)

        return max(1, estimated_lines)


def detect_compression(file_path: Path) -> Optional[str]:
    """Detect file compression type.

    Args:
        file_path: Path to file

    Returns:
        Compression type or None if uncompressed
    """
    if file_path.suffix == ".gz":
        return "gzip"
    return None


def smart_open(file_path: Path, mode: str = "rt"):
    """Open file with automatic compression detection.

    Args:
        file_path: Path to file
        mode: File mode

    Returns:
        File object
    """
    compression = detect_compression(file_path)
    if compression == "gzip":
        return gzip.open(file_path, mode)
    return open(file_path, mode)


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries.

    Args:
        dict1: First dictionary
        dict2: Second dictionary

    Returns:
        Merged dictionary
    """
    merged = dict1.copy()

    for key, value in dict2.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_dicts(merged[key], value)
        else:
            merged[key] = value

    return merged


def format_bytes(size: int) -> str:
    """Format byte size to human readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f}{unit}"
        size /= 1024
    return f"{size:.2f}PB"


def parse_size(size_str: str) -> int:
    """Parse human readable size string to bytes.

    Args:
        size_str: Size string (e.g., "1.5GB")

    Returns:
        Size in bytes

    Raises:
        ValueError: If size string is invalid
    """
    units = {
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
        "PB": 1024**5,
    }

    match = re.match(r"^([\d.]+)([A-Z]+)$", size_str.upper())
    if not match:
        raise ValueError(f"Invalid size string: {size_str}")

    size, unit = match.groups()
    if unit not in units:
        raise ValueError(f"Invalid size unit: {unit}")

    return int(float(size) * units[unit])


def is_json_line(line: str) -> bool:
    """Check if string is valid JSON.

    Args:
        line: String to check

    Returns:
        True if valid JSON
    """
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


def get_log_patterns() -> Dict[str, str]:
    """Get common log patterns.

    Returns:
        Dictionary of pattern names and regex patterns
    """
    return {
        "timestamp": r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        "ip": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "url": r"https?://(?:[\w-]+\.)+[\w-]+(?:/[\w-./?%&=]*)?",
        "uuid": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "mac_address": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    }


if __name__ == "__main__":
    # Example usage
    with timer("Processing"):
        result = parse_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
    print(result)
