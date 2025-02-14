from pathlib import Path
from typing import Union, Iterator, BinaryIO, TextIO, Optional, List, Dict, Any
import gzip
import bz2
import lzma
import mmap
import os
import stat
import hashlib
from datetime import datetime
import logging
import json
from contextlib import contextmanager

from .constants import FILE_EXTENSIONS
from .helpers import format_bytes

logger = logging.getLogger(__name__)

class FileError(Exception):
    """Base exception for file operations"""
    pass

class FileReader:
    """Efficient file reader with support for various formats"""
    
    def __init__(self, chunk_size: int = 8192):
        """Initialize file reader.
        
        Args:
            chunk_size: Size of chunks to read
        """
        self.chunk_size = chunk_size
        
    def read_lines(
        self,
        file_path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> Iterator[str]:
        """Read file lines efficiently.
        
        Args:
            file_path: Path to file
            encoding: File encoding
            
        Yields:
            Lines from file
            
        Raises:
            FileError: If file cannot be read
        """
        path = Path(file_path)
        
        try:
            if is_compressed(path):
                yield from self._read_compressed(path, encoding)
            else:
                yield from self._read_text(path, encoding)
        except Exception as e:
            raise FileError(f"Error reading file {path}: {str(e)}") from e
            
    def _read_text(self, path: Path, encoding: str) -> Iterator[str]:
        """Read plain text file"""
        with open(path, 'rb') as f:
            # Try memory mapping first
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    remainder = ''
                    for chunk in iter(lambda: mm.read(self.chunk_size), b''):
                        chunk = remainder + chunk.decode(encoding)
                        lines = chunk.split('\n')
                        remainder = lines.pop()
                        yield from lines
                    if remainder:
                        yield remainder
                return
            except (OSError, ValueError):
                # Fall back to normal reading if memory mapping fails
                pass
            
            # Normal reading
            remainder = ''
            for chunk in iter(lambda: f.read(self.chunk_size), b''):
                chunk = remainder + chunk.decode(encoding)
                lines = chunk.split('\n')
                remainder = lines.pop()
                yield from lines
            if remainder:
                yield remainder
                
    def _read_compressed(self, path: Path, encoding: str) -> Iterator[str]:
        """Read compressed file"""
        open_func = get_compression_opener(path)
        
        with open_func(path, 'rt', encoding=encoding) as f:
            yield from f

def is_compressed(path: Path) -> bool:
    """Check if file is compressed.
    
    Args:
        path: Path to check
        
    Returns:
        True if file is compressed
    """
    compression_extensions = {'.gz', '.bz2', '.xz'}
    return path.suffix in compression_extensions

def get_compression_opener(path: Path):
    """Get appropriate opener for compressed file.
    
    Args:
        path: Path to compressed file
        
    Returns:
        File opener function
        
    Raises:
        ValueError: If compression type unknown
    """
    if path.suffix == '.gz':
        return gzip.open
    elif path.suffix == '.bz2':
        return bz2.open
    elif path.suffix == '.xz':
        return lzma.open
    else:
        raise ValueError(f"Unknown compression type: {path.suffix}")

def scan_directory(
    directory: Union[str, Path],
    pattern: str = "*",
    recursive: bool = True
) -> Iterator[Path]:
    """Scan directory for files.
    
    Args:
        directory: Directory to scan
        pattern: Glob pattern for matching files
        recursive: Whether to scan recursively
        
    Yields:
        Matching file paths
    """
    path = Path(directory)
    
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")
        
    if recursive:
        yield from path.rglob(pattern)
    else:
        yield from path.glob(pattern)

def get_file_info(path: Union[str, Path]) -> Dict[str, Any]:
    """Get detailed file information.
    
    Args:
        path: Path to file
        
    Returns:
        Dictionary of file information
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    path = Path(path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
        
    stat_result = path.stat()
    
    return {
        'name': path.name,
        'path': str(path.absolute()),
        'size': stat_result.st_size,
        'size_human': format_bytes(stat_result.st_size),
        'created': datetime.fromtimestamp(stat_result.st_ctime),
        'modified': datetime.fromtimestamp(stat_result.st_mtime),
        'accessed': datetime.fromtimestamp(stat_result.st_atime),
        'mime_type': get_mime_type(path),
        'is_compressed': is_compressed(path),
        'permissions': stat.filemode(stat_result.st_mode),
        'checksum': calculate_checksum(path)
    }

def get_mime_type(path: Path) -> str:
    """Get MIME type for file.
    
    Args:
        path: Path to file
        
    Returns:
        MIME type string
    """
    return FILE_EXTENSIONS.get(path.suffix.lstrip('.'), 'application/octet-stream')

def calculate_checksum(
    path: Path,
    algorithm: str = 'sha256',
    chunk_size: int = 8192
) -> str:
    """Calculate file checksum.
    
    Args:
        path: Path to file
        algorithm: Hash algorithm to use
        chunk_size: Size of chunks to read
        
    Returns:
        Hexadecimal checksum string
    """
    hash_func = getattr(hashlib, algorithm)()
    
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            hash_func.update(chunk)
            
    return hash_func.hexdigest()

@contextmanager
def atomic_write(
    path: Union[str, Path],
    mode: str = 'w',
    encoding: Optional[str] = None,
    **kwargs
) -> Iterator[TextIO]:
    """Atomically write to file.
    
    Args:
        path: Path to file
        mode: File mode
        encoding: File encoding
        **kwargs: Additional arguments for open()
        
    Yields:
        File object for writing
    """
    path = Path(path)
    temp_path = path.with_suffix(path.suffix + '.tmp')
    
    try:
        with open(temp_path, mode, encoding=encoding, **kwargs) as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
            
        temp_path.replace(path)
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass

def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure directory exists.
    
    Args:
        path: Directory path
        
    Returns:
        Path object
        
    Raises:
        OSError: If directory cannot be created
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path

class RotatingFileWriter:
    """Writer that rotates files based on size or time"""
    
    def __init__(
        self,
        base_path: Union[str, Path],
        max_size: int = 100 * 1024 * 1024,  # 100MB
        backup_count: int = 5,
        compress: bool = True
    ):
        """Initialize rotating writer.
        
        Args:
            base_path: Base path for files
            max_size: Maximum file size in bytes
            backup_count: Number of backup files to keep
            compress: Whether to compress rotated files
        """
        self.base_path = Path(base_path)
        self.max_size = max_size
        self.backup_count = backup_count
        self.compress = compress
        self._current_size = 0
        
        # Open initial file
        self._ensure_file()
        
    def write(self, data: str) -> None:
        """Write data to file.
        
        Args:
            data: Data to write
        """
        data_size = len(data.encode('utf-8'))
        
        if self._current_size + data_size > self.max_size:
            self._rotate()
            
        self._file.write(data)
        self._file.flush()
        self._current_size += data_size
        
    def _ensure_file(self) -> None:
        """Ensure current file is open"""
        self._file = open(self.base_path, 'a', encoding='utf-8')
        self._current_size = self.base_path.stat().st_size
        
    def _rotate(self) -> None:
        """Rotate files"""
        self._file.close()
        
        # Delete oldest backup if it exists
        oldest = self.base_path.with_suffix(f'.{self.backup_count}')
        if oldest.exists():
            oldest.unlink()
            
        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            backup = self.base_path.with_suffix(f'.{i}')
            if backup.exists():
                new_name = self.base_path.with_suffix(f'.{i + 1}')
                backup.rename(new_name)
                
                if self.compress and i == 1:
                    # Compress the rotated file
                    with open(new_name, 'rb') as f_in:
                        with gzip.open(
                            str(new_name) + '.gz', 'wb'
                        ) as f_out:
                            f_out.write(f_in.read())
                    new_name.unlink()
        
        # Rotate current file
        self.base_path.rename(self.base_path.with_suffix('.1'))
        
        # Open new file
        self._ensure_file()
        
    def close(self) -> None:
        """Close current file"""
        self._file.close()

def tail(
    path: Union[str, Path],
    lines: int = 10,
    chunk_size: int = 8192
) -> List[str]:
    """Read last N lines of file efficiently.
    
    Args:
        path: Path to file
        lines: Number of lines to read
        chunk_size: Size of chunks to read
        
    Returns:
        List of last N lines
    """
    path = Path(path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
        
    if lines <= 0:
        return []
        
    with open(path, 'rb') as f:
        # Seek to end of file
        f.seek(0, os.SEEK_END)
        file_size = remaining_size = f.tell()
        
        result = []
        chunk = b''
        
        while remaining_size > 0 and len(result) < lines:
            # Calculate chunk size
            read_size = min(chunk_size, remaining_size)
            
            # Seek backwards and read chunk
            f.seek(-read_size, os.SEEK_CUR)
            chunk = f.read(read_size) + chunk
            
            # Move cursor back
            f.seek(-read_size, os.SEEK_CUR)
            
            # Update remaining size
            remaining_size -= read_size
            
            # Split into lines
            result = chunk.decode('utf-8').splitlines() + result
            
        return result[-lines:]

if __name__ == '__main__':
    # Example usage
    reader = FileReader()
    
    # Read lines from file
    with atomic_write('test.log') as f:
        f.write('Line 1\nLine 2\nLine 3\n')
        
    for line in reader.read_lines('test.log'):
        print(line)
        
    # Get file info
    print(json.dumps(get_file_info('test.log'), default=str, indent=2))