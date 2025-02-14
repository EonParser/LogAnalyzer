import os
from typing import List, Dict, Any, Optional, Tuple, Union
import re
import json
import hashlib
import base64
from collections import Counter

def truncate(text: str, max_length: int, suffix: str = '...', word_boundary: bool = True) -> str:
    """Truncate text at specified length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add to truncated text
        word_boundary: Whether to truncate at word boundary
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
        
    if not word_boundary:
        return text[:max_length - len(suffix)] + suffix
        
    end = max_length - len(suffix)
    while end > 0 and not text[end].isspace():
        end -= 1
    return text[:end].rstrip() + suffix

def normalize_whitespace(text: str) -> str:
    """Normalize multiple whitespace characters into single space.
    
    Args:
        text: Text to normalize
        
    Returns:
        Text with normalized whitespace
    """
    return ' '.join(text.split())

def extract_between(text: str, start: str, end: str, include_markers: bool = False) -> List[str]:
    """Extract text between start and end markers.
    
    Args:
        text: Text to search
        start: Start marker
        end: End marker
        include_markers: Whether to include markers in result
        
    Returns:
        List of extracted strings
    """
    pattern = f'{re.escape(start)}(.*?){re.escape(end)}'
    matches = re.finditer(pattern, text, re.DOTALL)
    
    if include_markers:
        return [f"{start}{m.group(1)}{end}" for m in matches]
    return [m.group(1) for m in matches]

def find_urls(text: str) -> List[str]:
    """Find URLs in text.
    
    Args:
        text: Text to search
        
    Returns:
        List of found URLs
    """
    url_pattern = (
        r'https?://'  # Protocol
        r'(?:[\w-]+\.)+[\w-]+'  # Domain
        r'(?:/[^\s<>"\'])*'  # Path
    )
    return re.findall(url_pattern, text)

def mask_sensitive_data(text: str, patterns: Dict[str, str], mask: str = '***') -> str:
    """Mask sensitive data in text.
    
    Args:
        text: Text to mask
        patterns: Dictionary of pattern names and regex patterns
        mask: Mask to apply
        
    Returns:
        Masked text
    """
    result = text
    for pattern in patterns.values():
        result = re.sub(pattern, mask, result)
    return result

def sanitize_filename(filename: str, replacement: str = '_', max_length: int = 255) -> str:
    """Sanitize filename by removing invalid characters.
    
    Args:
        filename: Filename to sanitize
        replacement: Character to replace invalid chars with
        max_length: Maximum filename length
        
    Returns:
        Sanitized filename
    """
    invalid_chars = r'[<>:"/\\|?*\x00-\x1F]'
    sanitized = re.sub(invalid_chars, replacement, filename)
    
    # Remove multiple replacements
    sanitized = re.sub(f'{replacement}+', replacement, sanitized)
    
    # Trim length if needed
    if len(sanitized) > max_length:
        base, ext = os.path.splitext(sanitized)
        max_base = max_length - len(ext)
        sanitized = base[:max_base] + ext
        
    return sanitized.strip(replacement)

def extract_fields(text: str, patterns: Dict[str, str]) -> Dict[str, str]:
    """Extract fields from text using patterns.
    
    Args:
        text: Text to extract from
        patterns: Dictionary of field names and patterns
        
    Returns:
        Dictionary of extracted fields
    """
    result = {}
    for field, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            result[field] = match.group(1) if match.groups() else match.group(0)
    return result

def compute_similarity(text1: str, text2: str) -> float:
    """Compute similarity between two strings using Jaccard similarity.
    
    Args:
        text1: First text
        text2: Second text
        
    Returns:
        Similarity score between 0 and 1
    """
    set1 = set(text1.lower().split())
    set2 = set(text2.lower().split())
    
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    
    return intersection / union if union > 0 else 0.0

def find_patterns(text: str, min_length: int = 3) -> List[str]:
    """Find repeated patterns in text.
    
    Args:
        text: Text to analyze
        min_length: Minimum pattern length
        
    Returns:
        List of found patterns
    """
    words = text.split()
    patterns = []
    
    for i in range(len(words)):
        for j in range(i + min_length, len(words) + 1):
            pattern = ' '.join(words[i:j])
            if text.count(pattern) > 1:
                patterns.append(pattern)
    
    return sorted(set(patterns), key=len, reverse=True)

def tokenize(text: str, min_length: int = 1, lowercase: bool = True) -> List[str]:
    """Tokenize text into words.
    
    Args:
        text: Text to tokenize
        min_length: Minimum token length
        lowercase: Whether to convert to lowercase
        
    Returns:
        List of tokens
    """
    text = text.lower() if lowercase else text
    words = re.findall(r'\b\w+\b', text)
    return [w for w in words if len(w) >= min_length]

def find_anomalies(text: str, reference_text: str, threshold: float = 0.1) -> List[str]:
    """Find words with significantly different frequencies.
    
    Args:
        text: Text to analyze
        reference_text: Reference text for comparison
        threshold: Frequency difference threshold
        
    Returns:
        List of anomalous words
    """
    text_words = Counter(tokenize(text))
    ref_words = Counter(tokenize(reference_text))
    
    text_total = sum(text_words.values())
    ref_total = sum(ref_words.values())
    
    anomalies = []
    for word, count in text_words.items():
        text_freq = count / text_total
        ref_freq = ref_words.get(word, 0) / ref_total if ref_total > 0 else 0
        if abs(text_freq - ref_freq) > threshold:
            anomalies.append(word)
            
    return anomalies

def anonymize_text(text: str, patterns: Dict[str, str], salt: Optional[str] = None) -> str:
    """Anonymize sensitive data using consistent hashing.
    
    Args:
        text: Text to anonymize
        patterns: Dictionary of patterns to anonymize
        salt: Optional salt for hashing
        
    Returns:
        Anonymized text
    """
    result = text
    for name, pattern in patterns.items():
        def replace(match: re.Match) -> str:
            value = match.group(0)
            if salt:
                value = f"{value}{salt}"
            
            hash_obj = hashlib.sha256(value.encode())
            hash_str = base64.b64encode(hash_obj.digest())[:8].decode()
            return f"[{name}_{hash_str}]"
            
        result = re.sub(pattern, replace, result)
    return result

def diff_strings(text1: str, text2: str) -> List[Tuple[str, str]]:
    """Find differences between two strings.
    
    Args:
        text1: First text
        text2: Second text
        
    Returns:
        List of (operation, value) tuples
    """
    from difflib import SequenceMatcher
    matcher = SequenceMatcher(None, text1, text2)
    
    result = []
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == 'equal':
            result.append(('=', text1[i1:i2]))
        elif op == 'delete':
            result.append(('-', text1[i1:i2]))
        elif op == 'insert':
            result.append(('+', text2[j1:j2]))
        elif op == 'replace':
            result.append(('-', text1[i1:i2]))
            result.append(('+', text2[j1:j2]))
    return result

def format_time_delta(delta: float, precision: int = 2, short: bool = False) -> str:
    """Format time delta in human readable format.
    
    Args:
        delta: Time delta in seconds
        precision: Number of units to show
        short: Whether to use short format
        
    Returns:
        Formatted string
    """
    units = [
        (60, 'minute', 'm'),
        (1, 'second', 's')
    ]
    
    parts = []
    remaining = int(delta)
    
    for value, name, short_name in units:
        if remaining >= value:
            count = remaining // value
            remaining %= value
            unit = short_name if short else f" {name}{'s' if count != 1 else ''}"
            parts.append(f"{count}{unit}")
            
            if len(parts) >= precision:
                break
    
    return ' '.join(parts) if parts else f"0{'s' if short else ' seconds'}"

def parse_structured_text(text: str) -> Dict[str, str]:
    """Parse key-value structured text.
    
    Args:
        text: Text to parse
        
    Returns:
        Dictionary of parsed key-value pairs
    """
    pattern = r'''
        (?P<key>[^\s=]+)         # Key
        \s*=\s*                  # Equals
        (?:
            "(?P<quoted>[^"]*)"| # Quoted value
            (?P<simple>[^\s]*)   # Simple value
        )
    '''
    
    result = {}
    for match in re.finditer(pattern, text, re.VERBOSE):
        key = match.group('key')
        value = match.group('quoted') or match.group('simple')
        result[key] = value
    return result

def clean_control_chars(text: str, replacement: str = ' ', keep_newlines: bool = True) -> str:
    """Clean control characters from text.
    
    Args:
        text: Text to clean
        replacement: Replacement character
        keep_newlines: Whether to keep newlines
        
    Returns:
        Cleaned text
    """
    if keep_newlines:
        return ''.join(c if c == '\n' or c.isprintable() else replacement for c in text)
    return ''.join(c if c.isprintable() else replacement for c in text)

def find_potential_pii(text: str) -> Dict[str, List[str]]:
    """Find potential personally identifiable information.
    
    Args:
        text: Text to analyze
        
    Returns:
        Dictionary of PII type and found matches
    """
    patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
    }
    
    result = {}
    for pii_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            result[pii_type] = matches
    return result

def contains_json(text: str) -> Optional[Tuple[int, int]]:
    """Find JSON object in text.
    
    Args:
        text: Text to analyze
        
    Returns:
        Tuple of (start, end) positions if found, None otherwise
    """
    start = text.find('{')
    if start == -1:
        return None
        
    level = 0
    in_string = False
    escape = False
    
    for i in range(start, len(text)):
        char = text[i]
        
        if char == '\\' and not escape:
            escape = True
            continue
        
        if char == '"' and not escape:
            in_string = not in_string
            
        if not in_string:
            if char == '{':
                level += 1
            elif char == '}':
                level -= 1
                if level == 0:
                    try:
                        json.loads(text[start:i+1])
                        return (start, i+1)
                    except json.JSONDecodeError:
                        pass
        
        escape = False
    
    return None

def extract_numbered_items(text: str) -> List[str]:
    """Extract numbered items from text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of extracted items
    """
    pattern = r'(?m)^\s*\d+\.\s*(.+?)(?=\s*\d+\.|$)'
    return [match.group(1).strip() for match in re.finditer(pattern, text)]

if __name__ == '__main__':
    # Example usage
    text = "Hello, this is a test with an email: test@example.com"
    print(find_potential_pii(text))