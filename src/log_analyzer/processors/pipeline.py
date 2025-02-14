from typing import List, Callable, Optional
from ..parsers.base import LogEntry

class ProcessingStep:
    """Base class for log processing steps"""
    
    def __init__(self, name: str):
        self.name = name
        
    def process(self, entry: LogEntry) -> Optional[LogEntry]:
        """Process a log entry
        
        Args:
            entry: Log entry to process
            
        Returns:
            Processed entry or None if entry should be filtered out
        """
        raise NotImplementedError

class Pipeline:
    """Processing pipeline for log entries"""
    
    def __init__(self):
        self.steps: List[ProcessingStep] = []
        self._preprocessors: List[Callable[[LogEntry], None]] = []
        self._postprocessors: List[Callable[[LogEntry], None]] = []
        
    def add_step(self, step: ProcessingStep) -> None:
        """Add a processing step to the pipeline"""
        self.steps.append(step)
        
    def add_preprocessor(self, func: Callable[[LogEntry], None]) -> None:
        """Add a preprocessing function"""
        self._preprocessors.append(func)
        
    def add_postprocessor(self, func: Callable[[LogEntry], None]) -> None:
        """Add a postprocessing function"""
        self._postprocessors.append(func)
        
    def process(self, entry: LogEntry) -> Optional[LogEntry]:
        """Process a log entry through the pipeline
        
        Args:
            entry: Log entry to process
            
        Returns:
            Processed entry or None if filtered out
        """
        # Run preprocessors
        for preprocessor in self._preprocessors:
            preprocessor(entry)
            
        # Run processing steps
        current_entry = entry
        for step in self.steps:
            if current_entry is None:
                break
            current_entry = step.process(current_entry)
            
        # Run postprocessors if entry wasn't filtered
        if current_entry is not None:
            for postprocessor in self._postprocessors:
                postprocessor(current_entry)
                
        return current_entry

class FilterStep(ProcessingStep):
    """Filter log entries based on a predicate"""
    
    def __init__(self, name: str, predicate: Callable[[LogEntry], bool]):
        """Initialize filter step
        
        Args:
            name: Step name
            predicate: Function that returns True for entries to keep
        """
        super().__init__(name)
        self.predicate = predicate
        
    def process(self, entry: LogEntry) -> Optional[LogEntry]:
        """Filter entry based on predicate"""
        return entry if self.predicate(entry) else None

class TransformStep(ProcessingStep):
    """Transform log entries"""
    
    def __init__(self, 
                 name: str, 
                 transformer: Callable[[LogEntry], LogEntry]):
        """Initialize transform step
        
        Args:
            name: Step name
            transformer: Function to transform entries
        """
        super().__init__(name)
        self.transformer = transformer
        
    def process(self, entry: LogEntry) -> LogEntry:
        """Transform entry"""
        return self.transformer(entry)

class EnrichmentStep(ProcessingStep):
    """Enrich log entries with additional data"""
    
    def __init__(self, 
                 name: str,
                 enricher: Callable[[LogEntry], dict]):
        """Initialize enrichment step
        
        Args:
            name: Step name
            enricher: Function that returns data to add to entry
        """
        super().__init__(name)
        self.enricher = enricher
        
    def process(self, entry: LogEntry) -> LogEntry:
        """Enrich entry with additional data"""
        additional_data = self.enricher(entry)
        entry.metadata.update(additional_data)
        return entry