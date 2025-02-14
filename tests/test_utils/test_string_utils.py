import pytest
import json
from datetime import datetime, timedelta

from log_analyzer.utils.string_utils import (
    truncate,
    normalize_whitespace,
    extract_between,
    find_urls,
    mask_sensitive_data,
    sanitize_filename,
    extract_fields,
    compute_similarity,
    find_patterns,
    tokenize,
    find_anomalies,
    anonymize_text,
    diff_strings,
    format_time_delta,
    parse_structured_text,
    clean_control_chars,
    find_potential_pii,
    contains_json,
    extract_numbered_items
)

class TestBasicStringOperations:
    """Test basic string manipulation operations"""
    
    def test_truncate(self):
        """Test string truncation with various options"""
        text = "This is a very long text that needs to be truncated"
        
        # Basic truncation
        assert truncate(text, 20) == "This is a very..."
        
        # Word boundary truncation
        assert truncate(text, 15, word_boundary=True) == "This is a..."
        assert truncate(text, 25, word_boundary=True) == "This is a very long..."
        
        # Custom suffix
        assert truncate(text, 20, suffix=">>>") == "This is a very>>>"
        assert truncate(text, 20, suffix="") == "This is a very"
        
        # Edge cases
        assert truncate("", 10) == ""
        assert truncate("Short", 10) == "Short"
        assert truncate("A", 1, suffix="...") == "..."
    
    def test_normalize_whitespace(self):
        """Test whitespace normalization"""
        test_cases = [
            ("  Multiple   Spaces  ", "Multiple Spaces"),
            ("\tTabs\nNewlines", "Tabs Newlines"),
            ("No  Extra  Spaces", "No Extra Spaces"),
            ("   ", ""),
            ("", ""),
            ("\n\t\r", ""),
            ("One\tTab", "One Tab"),
            ("Mixed   Spaces\tand\nLines", "Mixed Spaces and Lines")
        ]
        
        for input_text, expected in test_cases:
            assert normalize_whitespace(input_text) == expected

class TestExtraction:
    """Test text extraction operations"""
    
    def test_extract_between(self):
        """Test extracting text between markers"""
        test_cases = [
            # Basic cases
            ("Start[content]End", "[", "]", ["content"]),
            ("[one][two][three]", "[", "]", ["one", "two", "three"]),
            
            # Nested markers
            ("outer(inner)outer", "(", ")", ["inner"]),
            ("a{b{c}d}e", "{", "}", ["b{c", "c"]),
            
            # No matches
            ("No markers here", "[", "]", []),
            ("", "(", ")", []),
            
            # Unmatched markers
            ("Start[End", "[", "]", []),
            ("Start]End[", "[", "]", [])
        ]
        
        for text, start, end, expected in test_cases:
            # Test without including markers
            result = extract_between(text, start, end)
            assert result == expected
            
            # Test with including markers
            if expected:
                with_markers = extract_between(text, start, end, include_markers=True)
                assert all(s in m and e in m for m, (s, e) in zip(with_markers, zip(expected, expected)))
    
    def test_find_urls(self):
        """Test URL detection"""
        test_text = """
        Visit https://example.com for more info.
        Alternative link: http://alt.example.com/path?q=123
        Another site: https://sub.domain.org/path/to/page#section
        Invalid: not.a.url and http:// incomplete
        """
        
        urls = find_urls(test_text)
        
        assert len(urls) == 3
        assert "https://example.com" in urls
        assert "http://alt.example.com/path?q=123" in urls
        assert "https://sub.domain.org/path/to/page#section" in urls
        
        # Edge cases
        assert find_urls("") == []
        assert find_urls("No URLs here") == []
        assert find_urls("http://") == []
        
        # Complex URLs
        complex_url = "https://user:pass@sub.example.com:8080/path?q=123&t=456#fragment"
        assert complex_url in find_urls(complex_url)

class TestSensitiveData:
    """Test sensitive data handling"""
    
    def test_mask_sensitive_data(self):
        """Test masking sensitive information"""
        text = """
        Password: secret123
        API Key: abcd-1234-efgh
        Credit Card: 4111-1111-1111-1111
        Email: user@example.com
        """
        
        patterns = {
            'password': r'Password:\s*\S+',
            'api_key': r'API Key:\s*\S+',
            'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
            'email': r'\S+@\S+\.\S+'
        }
        
        masked = mask_sensitive_data(text, patterns)
        
        assert "secret123" not in masked
        assert "abcd-1234-efgh" not in masked
        assert "4111-1111-1111-1111" not in masked
        assert "user@example.com" not in masked
        assert "***" in masked
        
        # Test custom mask
        custom_masked = mask_sensitive_data(text, patterns, mask="[REDACTED]")
        assert "[REDACTED]" in custom_masked
    
    def test_find_potential_pii(self):
        """Test PII detection"""
        text = """
        Contact Info:
        - Email: john.doe@example.com
        - Phone: 123-456-7890
        - SSN: 123-45-6789
        - Credit Card: 4111 1111 1111 1111
        - IP Address: 192.168.1.1
        """
        
        pii = find_potential_pii(text)
        
        assert 'email' in pii
        assert 'john.doe@example.com' in pii['email']
        
        assert 'phone' in pii
        assert '123-456-7890' in pii['phone']
        
        assert 'ssn' in pii
        assert '123-45-6789' in pii['ssn']
        
        assert 'credit_card' in pii
        assert '4111 1111 1111 1111' in pii['credit_card']
        
        assert 'ip_address' in pii
        assert '192.168.1.1' in pii['ip_address']

class TestFilenameOperations:
    """Test filename-related operations"""
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        test_cases = [
            # Invalid characters
            ('file<>:"/\\|?*name.txt', 'file_name.txt'),
            
            # Spaces and dots
            ('file name.txt', 'file name.txt'),
            ('file..name.txt', 'file_name.txt'),
            
            # Leading/trailing spaces and dots
            (' filename.txt ', 'filename.txt'),
            ('.filename.txt.', 'filename.txt'),
            
            # Long filenames
            ('a' * 300 + '.txt', 'a' * 251 + '.txt'),
            
            # Unicode characters
            ('文件.txt', '文件.txt'),
            
            # Edge cases
            ('', '_'),
            ('.', '_'),
            ('..', '_')
        ]
        
        for input_name, expected in test_cases:
            assert sanitize_filename(input_name) == expected

class TestTextAnalysis:
    """Test text analysis operations"""
    
    def test_compute_similarity(self):
        """Test string similarity computation"""
        test_cases = [
            # Identical strings
            ("text", "text", 1.0),
            
            # Similar strings
            ("hello world", "hello there world", 0.5),
            ("python programming", "python code", 0.33),
            
            # Different strings
            ("apple", "orange", 0.0),
            
            # Case sensitivity
            ("Text", "text", 0.0),
            
            # Empty strings
            ("", "", 0.0),
            ("text", "", 0.0)
        ]
        
        for text1, text2, expected in test_cases:
            similarity = compute_similarity(text1, text2)
            assert abs(similarity - expected) < 0.01
    
    def test_find_patterns(self):
        """Test pattern detection"""
        test_cases = [
            # Repeated phrases
            (
                "the cat and the dog and the cat",
                ["the cat", "and the"]
            ),
            
            # Multiple patterns
            (
                "red blue red green blue red",
                ["red blue", "blue red"]
            ),
            
            # Minimum length
            (
                "a a a b b b",
                []
            ),
            
            # No patterns
            (
                "all words are unique here",
                []
            )
        ]
        
        for text, expected_patterns in test_cases:
            patterns = find_patterns(text)
            assert all(p in patterns for p in expected_patterns)

class TestStringFormatting:
    """Test string formatting operations"""
    
    def test_format_time_delta(self):
        """Test time delta formatting"""
        test_cases = [
            # Basic cases
            (60, "1 minute"),
            (3600, "1 hour"),
            (3665, "1 hour 1 minute"),
            
            # Multiple units
            (3725, "1 hour 2 minutes 5 seconds"),
            
            # Short format
            ((60, True), "1m"),
            ((3600, True), "1h"),
            ((3665, True), "1h 1m"),
            
            # Precision
            ((3725, False, 1), "1 hour"),
            ((3725, False, 2), "1 hour 2 minutes"),
            
            # Edge cases
            (0, "0 seconds"),
            (0.1, "100 milliseconds"),
            (86400, "1 day")
        ]
        
        for test_input in test_cases:
            if isinstance(test_input, tuple):
                if len(test_input) == 2:
                    delta, short = test_input
                    result = format_time_delta(delta, short=short)
                else:
                    delta, short, precision = test_input
                    result = format_time_delta(delta, short=short, precision=precision)
            else:
                result = format_time_delta(test_input)
                
            assert result == test_cases[test_input]

class TestJSONOperations:
    """Test JSON-related operations"""
    
    def test_contains_json(self):
        """Test JSON detection and extraction"""
        test_cases = [
            # Valid JSON
            (
                'Before {"key": "value"} After',
                (7, 23)
            ),
            
            # Nested JSON
            (
                '{"outer": {"inner": "value"}}',
                (0, 31)
            ),
            
            # Invalid JSON
            (
                '{"invalid": missing quotes}',
                None
            ),
            
            # Multiple JSON objects (should find first)
            (
                '{"first": 1} {"second": 2}',
                (0, 12)
            ),
            
            # Edge cases
            (
                '',
                None
            ),
            (
                '{}',
                (0, 2)
            )
        ]
        
        for text, expected in test_cases:
            result = contains_json(text)
            if expected is None:
                assert result is None
            else:
                assert result == expected
                # Verify extracted JSON is valid
                start, end = result
                json.loads(text[start:end])

class TestPerformance:
    """Test performance characteristics"""
    
    def test_large_text_processing(self, benchmark):
        """Test performance with large text"""
        # Generate large text
        large_text = "word " * 10000
        
        def process_large_text():
            truncate(large_text, 100)
            normalize_whitespace(large_text)
            find_urls(large_text)
            tokenize(large_text)
            clean_control_chars(large_text)
        
        # Run benchmark
        benchmark(process_large_text)
        
    def test_memory_usage_with_large_text(self):
        """Test memory usage with large text"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process large text
        large_text = "word " * 100000
        results = []
        
        # Perform various operations
        results.append(truncate(large_text, 1000))
        results.append(normalize_whitespace(large_text))
        results.append(find_urls(large_text))
        results.append(tokenize(large_text))
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024

if __name__ == '__main__':
    pytest.main([__file__])