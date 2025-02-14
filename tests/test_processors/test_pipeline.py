import pytest
from datetime import datetime
from typing import Optional

from log_analyzer.parsers.base import LogEntry
from log_analyzer.processors.pipeline import (
    Pipeline,
    ProcessingStep,
    FilterStep,
    TransformStep,
    EnrichmentStep
)

@pytest.fixture
def sample_entry():
    """Create a sample log entry for testing"""
    return LogEntry(
        timestamp=datetime.now(),
        level="INFO",
        message="Test message",
        source="test",
        raw_data="raw log line",
        parsed_data={"key": "value"},
        metadata={"meta": "data"}
    )

class TestProcessingStep:
    """Test base processing step functionality"""
    
    def test_abstract_processing_step(self):
        """Test that ProcessingStep is abstract"""
        class CustomStep(ProcessingStep):
            pass
            
        with pytest.raises(TypeError):
            CustomStep("test")
    
    def test_custom_processing_step(self, sample_entry):
        """Test custom processing step implementation"""
        class CustomStep(ProcessingStep):
            def process(self, entry: LogEntry) -> Optional[LogEntry]:
                entry.message = f"Processed: {entry.message}"
                return entry
                
        step = CustomStep("custom")
        result = step.process(sample_entry)
        
        assert result.message == "Processed: Test message"

class TestFilterStep:
    """Test filter step functionality"""
    
    def test_filter_inclusion(self, sample_entry):
        """Test filter that includes entry"""
        step = FilterStep("test_filter", lambda e: True)
        result = step.process(sample_entry)
        
        assert result is sample_entry
    
    def test_filter_exclusion(self, sample_entry):
        """Test filter that excludes entry"""
        step = FilterStep("test_filter", lambda e: False)
        result = step.process(sample_entry)
        
        assert result is None
    
    def test_filter_by_level(self, sample_entry):
        """Test filtering by log level"""
        step = FilterStep(
            "level_filter",
            lambda e: e.level in {"ERROR", "CRITICAL"}
        )
        
        # Test INFO level (should be filtered out)
        assert step.process(sample_entry) is None
        
        # Test ERROR level (should be included)
        sample_entry.level = "ERROR"
        assert step.process(sample_entry) is sample_entry

class TestTransformStep:
    """Test transform step functionality"""
    
    def test_simple_transform(self, sample_entry):
        """Test simple transformation"""
        def transformer(entry: LogEntry) -> LogEntry:
            entry.level = "DEBUG"
            return entry
            
        step = TransformStep("test_transform", transformer)
        result = step.process(sample_entry)
        
        assert result.level == "DEBUG"
    
    def test_chained_transforms(self, sample_entry):
        """Test multiple transformations in sequence"""
        def transform1(entry: LogEntry) -> LogEntry:
            entry.level = "DEBUG"
            return entry
            
        def transform2(entry: LogEntry) -> LogEntry:
            entry.message = entry.message.upper()
            return entry
            
        pipeline = Pipeline()
        pipeline.add_step(TransformStep("t1", transform1))
        pipeline.add_step(TransformStep("t2", transform2))
        
        result = pipeline.process(sample_entry)
        
        assert result.level == "DEBUG"
        assert result.message == "TEST MESSAGE"

class TestEnrichmentStep:
    """Test enrichment step functionality"""
    
    def test_basic_enrichment(self, sample_entry):
        """Test basic metadata enrichment"""
        def enricher(entry: LogEntry) -> dict:
            return {"enriched": True}
            
        step = EnrichmentStep("test_enrich", enricher)
        result = step.process(sample_entry)
        
        assert result.metadata["enriched"] is True
        
    def test_enrichment_merge(self, sample_entry):
        """Test merging of enrichment data"""
        def enricher(entry: LogEntry) -> dict:
            return {"new_key": "new_value"}
            
        step = EnrichmentStep("test_enrich", enricher)
        result = step.process(sample_entry)
        
        assert result.metadata["meta"] == "data"  # Original data preserved
        assert result.metadata["new_key"] == "new_value"  # New data added

class TestPipeline:
    """Test pipeline functionality"""
    
    def test_empty_pipeline(self, sample_entry):
        """Test pipeline with no steps"""
        pipeline = Pipeline()
        result = pipeline.process(sample_entry)
        
        assert result is sample_entry
    
    def test_pipeline_preprocessing(self, sample_entry):
        """Test pipeline preprocessors"""
        pipeline = Pipeline()
        processed_entries = []
        
        def preprocessor(entry: LogEntry):
            processed_entries.append("pre")
            entry.message = "Preprocessed"
            
        pipeline.add_preprocessor(preprocessor)
        result = pipeline.process(sample_entry)
        
        assert len(processed_entries) == 1
        assert result.message == "Preprocessed"
    
    def test_pipeline_postprocessing(self, sample_entry):
        """Test pipeline postprocessors"""
        pipeline = Pipeline()
        processed_entries = []
        
        def postprocessor(entry: LogEntry):
            processed_entries.append("post")
            entry.message = "Postprocessed"
            
        pipeline.add_postprocessor(postprocessor)
        result = pipeline.process(sample_entry)
        
        assert len(processed_entries) == 1
        assert result.message == "Postprocessed"
    
    def test_pipeline_step_order(self, sample_entry):
        """Test that pipeline steps are executed in order"""
        pipeline = Pipeline()
        execution_order = []
        
        def step1(entry: LogEntry) -> LogEntry:
            execution_order.append(1)
            return entry
            
        def step2(entry: LogEntry) -> LogEntry:
            execution_order.append(2)
            return entry
            
        pipeline.add_step(TransformStep("step1", step1))
        pipeline.add_step(TransformStep("step2", step2))
        pipeline.process(sample_entry)
        
        assert execution_order == [1, 2]
    
    def test_pipeline_error_handling(self, sample_entry):
        """Test pipeline error handling"""
        pipeline = Pipeline()
        
        def failing_step(entry: LogEntry) -> LogEntry:
            raise ValueError("Step failed")
            
        pipeline.add_step(TransformStep("failing", failing_step))
        
        with pytest.raises(ValueError):
            pipeline.process(sample_entry)
    
    def test_pipeline_filter_chain(self, sample_entry):
        """Test chain of filters"""
        pipeline = Pipeline()
        
        pipeline.add_step(FilterStep("f1", lambda e: e.level == "INFO"))
        pipeline.add_step(FilterStep("f2", lambda e: "key" in e.parsed_data))
        
        # Should pass both filters
        result1 = pipeline.process(sample_entry)
        assert result1 is sample_entry
        
        # Should be filtered out by first filter
        sample_entry.level = "DEBUG"
        result2 = pipeline.process(sample_entry)
        assert result2 is None

    def test_pipeline_thread_safety(self, sample_entry):
        """Test pipeline thread safety"""
        import threading
        import queue
        
        pipeline = Pipeline()
        results = queue.Queue()
        errors = queue.Queue()
        
        def transform(entry: LogEntry) -> LogEntry:
            entry.message = f"Thread: {threading.get_ident()}"
            return entry
            
        pipeline.add_step(TransformStep("thread_test", transform))
        
        def process_entry():
            try:
                result = pipeline.process(sample_entry)
                results.put(result)
            except Exception as e:
                errors.put(e)
        
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=process_entry)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        assert errors.empty()
        assert results.qsize() == 10

if __name__ == '__main__':
    pytest.main([__file__])