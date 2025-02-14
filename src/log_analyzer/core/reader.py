import gzip
import io
import mmap
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, TextIO, Union


class LogReader:
    """Efficient reader for large log files with streaming support"""

    def __init__(self, chunk_size: int = 8192):
        """Initialize the log reader

        Args:
            chunk_size: Size of chunks to read at a time (bytes)
        """
        self.chunk_size = chunk_size

    def read_lines(self, file_path: Union[str, Path]) -> Iterator[str]:
        """Read log file line by line using memory mapping

        Args:
            file_path: Path to log file

        Yields:
            Each line from the log file

        Raises:
            IOError: If file cannot be read
        """
        path = Path(file_path)

        if path.suffix == ".gz":
            yield from self._read_gzip(path)
        else:
            yield from self._read_text(path)

    def _read_text(self, path: Path) -> Iterator[str]:
        """Read a plain text log file"""
        with open(path, "rb") as f:
            try:
                # Try memory mapping first
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    buffer = io.StringIO(mm.read().decode("utf-8"))
                    for line in buffer:
                        yield line.rstrip("\r\n")
            except (OSError, ValueError):
                # Fall back to normal reading if memory mapping fails
                f.seek(0)
                remainder = ""
                for chunk in iter(lambda: f.read(self.chunk_size).decode("utf-8"), ""):
                    chunk = remainder + chunk
                    lines = chunk.split("\n")
                    remainder = lines.pop()
                    for line in lines:
                        yield line.rstrip("\r")
                if remainder:
                    yield remainder.rstrip("\r")

    def _read_gzip(self, path: Path) -> Iterator[str]:
        """Read a gzipped log file"""
        with gzip.open(path, "rt") as f:
            for line in f:
                yield line.rstrip("\r\n")

    def _stream_lines(self, file: Union[TextIO, BinaryIO]) -> Iterator[str]:
        """Stream lines from a file object"""
        buffer = ""

        while True:
            chunk = file.read(self.chunk_size)

            if not chunk:
                if buffer:
                    yield buffer
                break

            buffer += chunk if isinstance(chunk, str) else chunk.decode("utf-8")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                yield line.rstrip("\r")


class MultiFileReader:
    """Reader for handling multiple log files"""

    def __init__(self, chunk_size: int = 8192):
        self.reader = LogReader(chunk_size)

    def read_files(self, paths: list[Union[str, Path]]) -> Iterator[tuple[Path, str]]:
        """Read multiple log files

        Args:
            paths: List of file paths to read

        Yields:
            Tuples of (file_path, log_line)
        """
        for path in paths:
            path = Path(path)
            for line in self.reader.read_lines(path):
                yield path, line

    def read_directory(
        self, directory: Union[str, Path], pattern: str = "*.log*"
    ) -> Iterator[tuple[Path, str]]:
        """Read all matching log files in a directory

        Args:
            directory: Directory to scan
            pattern: Glob pattern for matching files

        Yields:
            Tuples of (file_path, log_line)
        """
        directory = Path(directory)
        paths = list(directory.glob(pattern))
        yield from self.read_files(paths)
