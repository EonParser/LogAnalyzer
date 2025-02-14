import pytest
from pathlib import Path
import gzip
import bz2
import os
import time
from datetime import datetime, timedelta

from log_analyzer.utils.file_utils import (
    FileReader,
    scan_directory,
    get_file_info,
    calculate_checksum,
    atomic_write,
    ensure_directory,
    RotatingFileWriter,
    tail,
    FileError
)

@pytest.fixture
def sample_file(tmp_path):
    """Create sample text file"""
    file_path = tmp_path / "sample.txt"
    content = "\n".join(f"Line {i+1}" for i in range(100))
    file_path.write_text(content)
    return file_path

@pytest.fixture
def compressed_files(tmp_path):
    """Create compressed test files"""
    content = "Test content\n" * 100
    
    # Create gzip file
    gz_path = tmp_path / "test.gz"
    with gzip.open(gz_path, 'wt') as f:
        f.write(content)
        
    # Create bz2 file
    bz2_path = tmp_path / "test.bz2"
    with bz2.open(bz2_path, 'wt') as f:
        f.write(content)
        
    return {
        'gz': gz_path,
        'bz2': bz2_path
    }

class TestFileReader:
    """Test FileReader functionality"""
    
    def test_read_text_file(self, sample_file):
        """Test reading plain text file"""
        reader = FileReader()
        lines = list(reader.read_lines(sample_file))
        
        assert len(lines) == 100
        assert lines[0] == "Line 1"
        assert lines[-1] == "Line 100"
    
    def test_read_compressed_files(self, compressed_files):
        """Test reading compressed files"""
        reader = FileReader()
        
        # Test gzip
        gz_lines = list(reader.read_lines(compressed_files['gz']))
        assert len(gz_lines) == 100
        assert all(line == "Test content" for line in gz_lines)
        
        # Test bz2
        bz2_lines = list(reader.read_lines(compressed_files['bz2']))
        assert len(bz2_lines) == 100
        assert all(line == "Test content" for line in bz2_lines)
    
    def test_invalid_file(self):
        """Test handling of invalid files"""
        reader = FileReader()
        
        with pytest.raises(FileError):
            list(reader.read_lines('nonexistent.txt'))
    
    def test_different_encodings(self, tmp_path):
        """Test reading files with different encodings"""
        test_file = tmp_path / "encoded.txt"
        content = "Hello, 世界\n"
        
        # Write with UTF-8
        test_file.write_text(content, encoding='utf-8')
        reader = FileReader()
        lines = list(reader.read_lines(test_file, encoding='utf-8'))
        assert lines[0] == "Hello, 世界"
        
        # Write with different encoding
        test_file.write_text(content, encoding='utf-16')
        lines = list(reader.read_lines(test_file, encoding='utf-16'))
        assert lines[0] == "Hello, 世界"

class TestDirectoryOperations:
    """Test directory-related operations"""
    
    def test_scan_directory(self, tmp_path):
        """Test directory scanning"""
        # Create test files
        (tmp_path / "file1.txt").touch()
        (tmp_path / "file2.log").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").touch()
        
        # Test non-recursive scan
        files = list(scan_directory(tmp_path, pattern="*.txt", recursive=False))
        assert len(files) == 1
        assert files[0].name == "file1.txt"
        
        # Test recursive scan
        files = list(scan_directory(tmp_path, pattern="*.txt", recursive=True))
        assert len(files) == 2
        assert {f.name for f in files} == {"file1.txt", "file3.txt"}
    
    def test_ensure_directory(self, tmp_path):
        """Test directory creation"""
        test_dir = tmp_path / "test" / "nested" / "dir"
        created_dir = ensure_directory(test_dir)
        
        assert created_dir.exists()
        assert created_dir.is_dir()
        
        # Test idempotency
        ensure_directory(test_dir)
        assert test_dir.exists()

class TestFileInfo:
    """Test file information retrieval"""
    
    def test_get_file_info(self, sample_file):
        """Test getting file information"""
        info = get_file_info(sample_file)
        
        assert info['name'] == "sample.txt"
        assert info['size'] > 0
        assert isinstance(info['created'], datetime)
        assert isinstance(info['modified'], datetime)
        assert isinstance(info['accessed'], datetime)
        assert info['mime_type'] == "text/plain"
        assert not info['is_compressed']
        assert len(info['checksum']) == 64  # SHA-256
    
    def test_calculate_checksum(self, sample_file):
        """Test checksum calculation"""
        checksum1 = calculate_checksum(sample_file)
        checksum2 = calculate_checksum(sample_file, algorithm='md5')
        
        assert len(checksum1) == 64  # SHA-256
        assert len(checksum2) == 32  # MD5
        
        # Modify file
        with open(sample_file, 'a') as f:
            f.write("\nNew line")
            
        checksum3 = calculate_checksum(sample_file)
        assert checksum1 != checksum3

class TestFileWriting:
    """Test file writing operations"""
    
    def test_atomic_write(self, tmp_path):
        """Test atomic file writing"""
        test_file = tmp_path / "atomic.txt"
        
        # Write file atomically
        with atomic_write(test_file) as f:
            f.write("Test content")
            
        assert test_file.exists()
        assert test_file.read_text() == "Test content"
        
        # Test failure case
        with pytest.raises(Exception):
            with atomic_write(test_file) as f:
                f.write("New content")
                raise Exception("Simulated error")
                
        # Original content should be preserved
        assert test_file.read_text() == "Test content"
    
    def test_rotating_writer(self, tmp_path):
        """Test rotating file writer"""
        base_path = tmp_path / "rotating.log"
        writer = RotatingFileWriter(
            base_path,
            max_size=100,  # Small size for testing
            backup_count=3
        )
        
        # Write enough data to cause multiple rotations
        for i in range(10):
            writer.write(f"Line {i}\n" * 5)
            
        writer.close()
        
        # Check files
        assert base_path.exists()
        assert (tmp_path / "rotating.log.1").exists()
        assert (tmp_path / "rotating.log.2").exists()
        assert (tmp_path / "rotating.log.3").exists()
        assert not (tmp_path / "rotating.log.4").exists()

class TestFileReading:
    """Test file reading operations"""
    
    def test_tail(self, sample_file):
        """Test reading last lines of file"""
        # Read last 10 lines
        last_lines = tail(sample_file, lines=10)
        assert len(last_lines) == 10
        assert last_lines[-1] == "Line 100"
        
        # Read more lines than file contains
        all_lines = tail(sample_file, lines=200)
        assert len(all_lines) == 100
        
        # Test with empty file
        empty_file = sample_file.parent / "empty.txt"
        empty_file.touch()
        assert tail(empty_file) == []
    
    def test_tail_nonexistent_file(self):
        """Test tail with nonexistent file"""
        with pytest.raises(FileNotFoundError):
            tail("nonexistent.txt")

if __name__ == '__main__':
    pytest.main([__file__])