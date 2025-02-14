import pytest
import time
from pathlib import Path
import random
from datetime import datetime, timedelta
import gzip
import multiprocessing
import psutil
import os

from log_analyzer.core.analyzer import LogAnalyzer
from log_analyzer.parsers.base import ParserFactory
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.nginx import NginxAccessLogParser
from log_analyzer.processors.pipeline import Pipeline, TransformStep
from log_analyzer.processors.transformers import TransformerFactory

def generate_apache_log_line(timestamp):
    """Generate a random Apache log line"""
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    paths = ['/api/users', '/api/products', '/api/orders', '/api/auth']
    status_codes = [200, 201, 400, 401, 403, 404, 500]
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'curl/7.64.1',
        'PostmanRuntime/7.29.2',
        'Apache-HttpClient/4.5.13'
    ]
    
    return (
        f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)} '
        f'- - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
        f'"{random.choice(methods)} {random.choice(paths)} HTTP/1.1" '
        f'{random.choice(status_codes)} {random.randint(100, 5000)} '
        f'"http://example.com" "{random.choice(user_agents)}"'
    )

@pytest.fixture
def large_log_file(tmp_path):
    """Create a large log file for performance testing"""
    log_file = tmp_path / "large_access.log"
    
    # Generate 100,000 log lines
    lines = []
    base_time = datetime.now()
    for i in range(100_000):
        timestamp = base_time + timedelta(seconds=i)
        lines.append(generate_apache_log_line(timestamp))
    
    log_file.write_text('\n'.join(lines))
    return log_file

@pytest.fixture
def compressed_log_file(tmp_path, large_log_file):
    """Create a compressed version of the large log file"""
    gz_file = tmp_path / "large_access.log.gz"
    with open(large_log_file, 'rb') as f_in:
        with gzip.open(gz_file, 'wb') as f_out:
            f_out.write(f_in.read())
    return gz_file

@pytest.fixture
def analyzer():
    """Create analyzer instance with all parsers"""
    parser_factory = ParserFactory()
    parser_factory.register_parser('apache', ApacheLogParser)
    parser_factory.register_parser('nginx', NginxAccessLogParser)
    return LogAnalyzer(parser_factory=parser_factory)

class TestParsingPerformance:
    """Test parsing performance"""
    
    def test_large_file_processing(self, analyzer, large_log_file, benchmark):
        """Test processing of large log file"""
        def process_file():
            return analyzer.analyze_file(large_log_file, parser_name='apache')
        
        results = benchmark(process_file)
        
        assert results['total_entries'] == 100_000
        assert results['errors']['count'] == 0
        
        # Calculate and print metrics
        entries_per_second = results['entries_per_second']
        print(f"\nProcessing speed: {entries_per_second:.2f} entries/second")
    
    def test_compressed_file_processing(self, analyzer, compressed_log_file, benchmark):
        """Test processing of compressed log file"""
        def process_compressed():
            return analyzer.analyze_file(compressed_log_file, parser_name='apache')
        
        results = benchmark(process_compressed)
        
        assert results['total_entries'] == 100_000
        assert results['errors']['count'] == 0

class TestMemoryUsage:
    """Test memory usage characteristics"""
    
    def test_memory_usage_large_file(self, analyzer, large_log_file):
        """Test memory usage with large file processing"""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        results = analyzer.analyze_file(large_log_file, parser_name='apache')
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Print memory usage statistics
        print(f"\nMemory usage increase: {memory_increase / 1024 / 1024:.2f} MB")
        print(f"Memory per entry: {memory_increase / results['total_entries'] / 1024:.2f} KB")
        
        # Memory should increase less than 100MB for 100k entries
        assert memory_increase < 100 * 1024 * 1024
    
    def test_memory_cleanup(self, analyzer, large_log_file):
        """Test memory cleanup after processing"""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process file multiple times
        for _ in range(5):
            results = analyzer.analyze_file(large_log_file, parser_name='apache')
        
        # Force garbage collection
        import gc
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable after multiple runs
        assert memory_increase < 150 * 1024 * 1024

class TestConcurrentProcessing:
    """Test concurrent processing performance"""
    
    def test_multi_worker_performance(self, analyzer, tmp_path, benchmark):
        """Test performance with different numbers of workers"""
        # Create multiple log files
        file_count = 10
        lines_per_file = 10_000
        
        for i in range(file_count):
            log_file = tmp_path / f"access_{i}.log"
            lines = []
            base_time = datetime.now()
            for j in range(lines_per_file):
                timestamp = base_time + timedelta(seconds=j)
                lines.append(generate_apache_log_line(timestamp))
            log_file.write_text('\n'.join(lines))
        
        def process_with_workers(workers):
            return analyzer.analyze_directory(
                tmp_path,
                pattern="*.log",
                max_workers=workers
            )
        
        # Test with different worker counts
        cpu_count = multiprocessing.cpu_count()
        worker_counts = [1, cpu_count // 2, cpu_count, cpu_count * 2]
        
        for workers in worker_counts:
            results = benchmark(
                process_with_workers,
                workers,
                rounds=3
            )
            
            total_entries = results['total_entries']
            print(f"\nWorkers: {workers}")
            print(f"Total entries: {total_entries}")
            print(f"Processing speed: {results['entries_per_second']:.2f} entries/second")

class TestPipelinePerformance:
    """Test pipeline processing performance"""
    
    def test_pipeline_complexity(self, analyzer, large_log_file, benchmark):
        """Test performance with different pipeline complexities"""
        # Create pipelines with different complexities
        pipelines = {
            'simple': Pipeline(),
            'medium': Pipeline(),
            'complex': Pipeline()
        }
        
        # Simple pipeline: just one transformation
        pipelines['simple'].add_step(
            TransformStep(
                'simple',
                TransformerFactory.create_standard_transformer()
            )
        )
        
        # Medium pipeline: multiple transformations
        medium_transformer = TransformerFactory.create_standard_transformer()
        pipelines['medium'].add_step(
            TransformStep('medium1', medium_transformer)
        )
        pipelines['medium'].add_step(
            TransformStep(
                'medium2',
                TransformerFactory.create_security_transformer()
            )
        )
        
        # Complex pipeline: many transformations and enrichments
        complex_transformer = TransformerFactory.create_web_access_transformer()
        pipelines['complex'].add_step(
            TransformStep('complex1', complex_transformer)
        )
        pipelines['complex'].add_step(
            TransformStep(
                'complex2',
                TransformerFactory.create_security_transformer()
            )
        )
        
        # Benchmark each pipeline
        for name, pipeline in pipelines.items():
            def process_with_pipeline():
                return analyzer.analyze_file(
                    large_log_file,
                    parser_name='apache',
                    pipeline=pipeline
                )
            
            results = benchmark(
                process_with_pipeline,
                rounds=3
            )
            
            print(f"\nPipeline: {name}")
            print(f"Processing speed: {results['entries_per_second']:.2f} entries/second")

if __name__ == '__main__':
    pytest.main([__file__, '-v'])